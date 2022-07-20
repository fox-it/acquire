import argparse
import base64
import contextlib
import io
import json
import logging
import multiprocessing
import os
import signal
import sys
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib import request
from urllib.error import HTTPError
from urllib.parse import urljoin
from queue import Empty as QueueEmptyError

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from dissect.util.stream import AlignedStream

try:
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn

    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        transient=True,
    )
except ImportError:
    progress = None

from acquire.crypt import FILE_MAGIC, FILE_VERSION, FOOTER_MAGIC, HEADER_MAGIC, c_acquire, key_fingerprint


log = logging.getLogger(__name__)


CHUNK_SIZE = 1024 * 1024 * 4
WORKER_COUNT = max(1, os.cpu_count() - 1)

STATUS_EXIT = 0
STATUS_INFO = 1
STATUS_START = 2
STATUS_UPDATE = 3


class VerifyError(Exception):
    pass


class EncryptedFile(AlignedStream):
    def __init__(self, fh, key_file=None, key_server=None):
        self.fh = fh
        self.key_file = key_file
        self.key_server = key_server

        self._file_header = None
        self._header = None
        self._footer = None
        self.digest = None

        if not key_file and not key_server:
            raise ValueError("Need either key or key server")

        file_header_buf = fh.read(len(c_acquire.file))
        self.file_header = c_acquire.file(file_header_buf)

        header_buf = fh.read(self.file_header.header_size)
        decrypted_header = decrypt_header(
            header_buf, self.file_header.key_digest, key_file=key_file, key_server=key_server
        )
        self.header = c_acquire.header(decrypted_header)

        size = None
        if self.fh.seekable():
            offset = fh.tell()
            fh.seek(-8, io.SEEK_END)
            self.footer = c_acquire.footer(fh)

            fh.seek(-8 - self.footer.length, io.SEEK_END)
            size = fh.tell() - offset
            self.digest = fh.read(self.footer.length)
            fh.seek(offset)

        self.cipher = AES.new(self.header.key, AES.MODE_GCM, nonce=self.header.iv)
        self.cipher.update(file_header_buf + header_buf)

        self.buffers = deque(maxlen=3)

        super().__init__(size)

    def seekable(self):
        return False

    def seek(self, pos, whence=io.SEEK_CUR):
        raise io.UnsupportedOperation("seeking is not allowed")

    def _read(self, offset, length):
        if not self.size:
            result = []

            while length:
                # Triple buffer the reads so that we can catch the last block.
                # Three buffers because the last three reads can be [CHUNK_SIZE, CHUNK_SIZE - n, 0].
                # We only want to check for the footer when we reach EOF in case of streaming or partial data.
                while len(self.buffers) != self.buffers.maxlen and not self.digest:
                    try:
                        chunk = self.fh.read(CHUNK_SIZE)
                    except EOFError:
                        chunk = b""

                    if chunk == b"":
                        last_block = b"".join(self.buffers)

                        footer_size = len(c_acquire.footer)
                        self.footer = c_acquire.footer(last_block[-footer_size:])
                        self.digest = last_block[-footer_size - self.footer.length : -footer_size]

                        self.buffers.clear()
                        self.buffers.append(last_block[: -footer_size - self.footer.length])
                        self.buffers.append(b"")
                        break

                    self.buffers.append(chunk)

                current_chunk = self.buffers.popleft()
                read_size = max(0, length)
                read_chunk = current_chunk[:read_size]
                remainder_chunk = current_chunk[read_size:]
                if remainder_chunk:
                    self.buffers.appendleft(remainder_chunk)

                result.append(read_chunk)
                length -= read_size

            return self.cipher.decrypt(b"".join(result))
        else:
            read_size = max(0, min(length, self.size - offset))
            return self.cipher.decrypt(self.fh.read(read_size))

    def chunks(self, chunk_size=CHUNK_SIZE):
        while True:
            chunk = self.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def verify(self):
        try:
            self.cipher.verify(self.digest)
        except ValueError:
            raise VerifyError("Digest check failed")

    @property
    def file_header(self):
        return self._file_header

    @file_header.setter
    def file_header(self, file_header):
        if file_header.magic != FILE_MAGIC:
            raise ValueError(f"Invalid file magic: {file_header.magic}")

        if file_header.version != FILE_VERSION:
            raise ValueError(f"Unsupported version: {file_header.version}")

        if file_header.header_type != c_acquire.HeaderType.PKCS1_OAEP:
            raise ValueError(f"Unsupported header type: {file_header.header_type}")

        self._file_header = file_header

    @property
    def header(self):
        return self._header

    @header.setter
    def header(self, header):
        if header.magic != HEADER_MAGIC:
            raise ValueError(f"Invalid header magic: {header.magic}")
        self._header = header

    @property
    def footer(self):
        return self._footer

    @footer.setter
    def footer(self, footer):
        if footer.magic != FOOTER_MAGIC:
            raise ValueError(f"Invalid footer magic: {footer}")
        self._footer = footer

    @property
    def timestamp(self):
        return datetime.fromtimestamp(self.file_header.timestamp, timezone.utc)


def decrypt_header(header, fingerprint, key_file=None, key_server=None):
    if not key_file and not key_server:
        raise ValueError("Need either key file or key server")

    if key_file:
        rsa_key = RSA.import_key(key_file.read_text())
        if key_fingerprint(rsa_key.public_key()) != fingerprint:
            raise ValueError("Key doesn't match fingerprint")
        return PKCS1_OAEP.new(rsa_key).decrypt(header)
    else:
        data = json.dumps({"fingerprint": fingerprint.hex(), "header": base64.b64encode(header).decode()}).encode(
            "utf-8"
        )

        url = urljoin(key_server, "/api/v1/decrypt")
        req = request.Request(url, data, headers={"Content-Type": "application/json"})
        try:
            resp = request.urlopen(req)
        except HTTPError as e:
            if e.code == 404:
                raise ValueError("Unknown key fingerprint")
            raise ValueError(f"Failed to decrypt header: {e}")
        result = json.loads(resp.read())

        return base64.b64decode(result["header"])


def worker(task_id, stop_event, status_queue, in_path, out_path, key_file=None, key_server=None, clobber=False):
    try:
        if out_path.exists() and not clobber:
            _info(status_queue, f"Output file already exists: {out_path}")
            return

        _update(status_queue, task_id, visible=True)
        success = False
        with in_path.open("rb") as infh:
            try:
                ef = EncryptedFile(infh, key_file=key_file, key_server=key_server)
            except Exception as e:
                _info(status_queue, f"{in_path} • Error opening encrypted file: {e}")
            _info(
                status_queue,
                f"{in_path} • File: {ef.file_header.magic.decode()} | {ef.file_header.header_type} | {ef.timestamp}",
            )
            _info(status_queue, f"{in_path} • Header: {ef.header.magic.decode()} | {ef.header.cipher_type}")
            _update(status_queue, task_id, total=ef.size)

            with out_path.open("wb") as outfh:
                _info(status_queue, f"{in_path} • Decrypting to {out_path}")
                _start(status_queue, task_id)
                try:
                    for chunk in ef.chunks():
                        if stop_event.is_set():
                            raise ValueError("stopping")
                        outfh.write(chunk)
                        _update(status_queue, task_id, advance=len(chunk))
                    ef.verify()
                    _info(status_queue, f"{in_path} • File verified OK!")
                    success = True
                except ValueError as e:
                    _info(status_queue, f"{in_path} • Error decrypting file: {e}")
                except VerifyError as e:
                    _info(status_queue, f"{in_path} • Verify error: {e}")
                    _info(status_queue, f"{in_path} • ! Output file should NOT be trusted")
                except Exception as e:
                    _info(status_queue, f"{in_path} • Unknown error: {e}")

        if not success:
            failed_path = out_path.with_suffix(f"{out_path.suffix}.failed")
            _info(status_queue, f"{in_path} • ! Renaming to {failed_path}")
            out_path.rename(failed_path)
    finally:
        _update(status_queue, task_id, visible=False)
        _exit(status_queue, task_id)


def _start(queue, task_id):
    queue.put_nowait((STATUS_START, task_id))


def _update(queue, task_id, *args, **kwargs):
    queue.put_nowait((STATUS_UPDATE, (task_id, args, kwargs)))


def _info(queue, msg):
    queue.put_nowait((STATUS_INFO, msg))


def _exit(queue, task_id):
    queue.put_nowait((STATUS_EXIT, task_id))


def setup_logging(logger, verbosity):
    if verbosity == 1:
        level = logging.ERROR
    elif verbosity == 2:
        level = logging.WARNING
    elif verbosity == 3:
        level = logging.INFO
    elif verbosity >= 4:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)
    logger.setLevel(level)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path, help="paths to encrypted files")
    parser.add_argument("-o", "--output", type=Path, help="optional path to output file")
    parser.add_argument("-c", "--clobber", action="store_true", help="overwrite existing output files")
    parser.add_argument("-ks", "--key-server", default="", help="URI for key server")
    parser.add_argument("-k", "--key-file", type=Path, help="path to PEM private key")
    parser.add_argument("-w", "--workers", type=int, default=WORKER_COUNT, help="maximum amount of workers")
    parser.add_argument("-v", "--verbose", action="count", default=3, help="increase output verbosity")
    args = parser.parse_args()

    setup_logging(log, args.verbose)

    if not progress:
        log.info("`rich` is not installed, progress will not be shown")

    if args.output and len(args.files) > 1:
        parser.exit("--output is only allowed when decrypting a single file")

    if not args.output:
        for path in args.files:
            if path.suffix != ".enc":
                parser.exit(f"File doesn't have .enc extension: {path}")

    if args.output:
        outputs = [args.output.resolve()]
    else:
        # Strip .enc extension
        outputs = [path.with_suffix("") for path in args.files]

    if not args.key_file and not args.key_server:
        parser.exit("Need either --key-file or --key-server")

    if args.key_file:
        if not args.key_file.is_file():
            parser.exit(f"{args.key_file} doesn't exist or is not a file")

        key_file = args.key_file
        key_server = None
    else:
        key_file = None
        key_server = args.key_server

    ctx = progress or contextlib.nullcontext()
    with ctx:
        signal_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        with multiprocessing.Manager() as mp, ProcessPoolExecutor(max_workers=args.workers) as executor:
            stop_event = mp.Event()
            status_queue = mp.Queue()
            tasks = []

            for in_path, out_path in zip(args.files, outputs):
                task_id = (
                    progress.add_task("decrypt", start=False, visible=False, filename=in_path.name)
                    if progress
                    else len(tasks)
                )
                executor.submit(
                    worker,
                    task_id,
                    stop_event,
                    status_queue,
                    in_path,
                    out_path,
                    key_file=key_file,
                    key_server=key_server,
                    clobber=args.clobber,
                )
                tasks.append(task_id)

            signal.signal(signal.SIGINT, signal_handler)

            while tasks:
                try:
                    cmd, args = status_queue.get(timeout=10)

                    if cmd == STATUS_EXIT:
                        tasks.remove(args)
                    elif cmd == STATUS_INFO:
                        if progress:
                            progress.console.log(args)
                        else:
                            log.info(args)
                    elif cmd == STATUS_START:
                        if progress:
                            progress.start_task(args)
                    elif cmd == STATUS_UPDATE:
                        task_id, args, kwargs = args
                        if progress:
                            progress.update(task_id, *args, **kwargs)
                except (QueueEmptyError, KeyboardInterrupt):
                    (progress.console.log if progress else log.info)("Stopping...")
                    stop_event.set()
                    executor.shutdown(wait=True, cancel_futures=True)
                    break


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
