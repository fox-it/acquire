from __future__ import annotations

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
import textwrap
from collections import defaultdict, deque
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty as QueueEmptyError
from queue import Queue
from typing import TYPE_CHECKING, BinaryIO
from urllib import request
from urllib.error import HTTPError
from urllib.parse import urljoin

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from dissect.util.stream import AlignedStream

try:
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )

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

from acquire.crypt import (
    FILE_MAGIC,
    FILE_VERSION,
    FOOTER_MAGIC,
    HEADER_MAGIC,
    c_acquire,
    key_fingerprint,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from threading import Event

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
    def __init__(self, fh: BinaryIO, key_file: Path | None = None, key_server: str | None = None) -> None:
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

    def seekable(self) -> bool:
        return False

    def seek(self, pos: int, whence: int = io.SEEK_CUR) -> int:
        raise io.UnsupportedOperation("seeking is not allowed")

    def _read(self, offset: int, length: int) -> bytes:
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
        read_size = max(0, min(length, self.size - offset))
        return self.cipher.decrypt(self.fh.read(read_size))

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        while True:
            chunk = self.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def verify(self) -> None:
        try:
            self.cipher.verify(self.digest)
        except ValueError:
            raise VerifyError("Digest check failed")

    @property
    def file_header(self) -> c_acquire.file:
        return self._file_header

    @file_header.setter
    def file_header(self, file_header: c_acquire.file) -> None:
        if file_header.magic != FILE_MAGIC:
            raise ValueError(f"Invalid file magic: {file_header.magic}")

        if file_header.version != FILE_VERSION:
            raise ValueError(f"Unsupported version: {file_header.version}")

        if file_header.header_type != c_acquire.HeaderType.PKCS1_OAEP:
            raise ValueError(f"Unsupported header type: {file_header.header_type}")

        self._file_header = file_header

    @property
    def header(self) -> c_acquire.header:
        return self._header

    @header.setter
    def header(self, header: c_acquire.header) -> None:
        if header.magic != HEADER_MAGIC:
            raise ValueError(f"Invalid header magic: {header.magic}")
        self._header = header

    @property
    def footer(self) -> c_acquire.footer:
        return self._footer

    @footer.setter
    def footer(self, footer: c_acquire.footer) -> None:
        if footer.magic != FOOTER_MAGIC:
            raise ValueError(f"Invalid footer magic: {footer}")
        self._footer = footer

    @property
    def timestamp(self) -> datetime:
        return datetime.fromtimestamp(self.file_header.timestamp, timezone.utc)


def decrypt_header(
    header: bytes, fingerprint: bytes, key_file: Path | None = None, key_server: str | None = None
) -> bytes:
    if not key_file and not key_server:
        raise ValueError("Need either key file or key server")

    if key_file:
        rsa_key = RSA.import_key(key_file.read_text())
        if key_fingerprint(rsa_key.public_key()) != fingerprint:
            raise ValueError("Key doesn't match fingerprint")
        return PKCS1_OAEP.new(rsa_key).decrypt(header)
    data = json.dumps({"fingerprint": fingerprint.hex(), "header": base64.b64encode(header).decode()}).encode("utf-8")

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


def check_existing(in_path: Path, out_path: Path, status_queue: multiprocessing.Queue) -> bool:
    if out_path.exists():
        _info(status_queue, f"Output file already exists: {out_path}")
        return True

    # If suffixes of the out_path do not correspond with the in_path suffixes (minus ".enc"),
    # we're probably dealing with a special custom filename. Therefore, do not check for the existence of the
    # decompressed filename
    if out_path.suffixes != in_path.suffixes[:-1]:
        return False

    # Check if acquire file is compressed (Path("file.tar.gz.enc").stem -> "file.tar.gz")
    # If it is compressed, check if decompressed file already exists
    if in_path.stem.endswith((".tgz", ".gz")) and (decompressed_file := out_path.with_suffix("")).exists():
        _info(status_queue, f"Decompressed file already exists: {decompressed_file}")
        return True

    return False


def worker(
    task_id: int,
    stop_event: Event,
    status_queue: Queue,
    in_path: Path,
    out_path: Path,
    key_file: Path | None = None,
    key_server: str | None = None,
    clobber: bool = False,
) -> None:
    success = False
    message = "An unknown error occurred"

    try:
        if check_existing(in_path, out_path, status_queue) and not clobber:
            message = "Output file or decompressed file already exists!"
            return

        _update(status_queue, task_id, visible=True)
        with in_path.open("rb") as infh:
            try:
                ef = EncryptedFile(infh, key_file=key_file, key_server=key_server)
            except Exception as e:
                message = f"Error opening encrypted file: {e}"
                _info(status_queue, f"{in_path} • {message}")
                return
            _info(
                status_queue,
                f"{in_path} • File: {ef.file_header.magic.decode()} | {ef.file_header.header_type} | {ef.timestamp}",
            )
            _info(status_queue, f"{in_path} • Header: {ef.header.magic.decode()} | {ef.header.cipher_type}")
            _update(status_queue, task_id, total=ef.size)

            try:
                with out_path.open("wb") as outfh:
                    _info(status_queue, f"{in_path} • Decrypting to {out_path}")
                    _start(status_queue, task_id)

                    for chunk in ef.chunks():
                        if stop_event.is_set():
                            raise ValueError("stopping")  # noqa: TRY301
                        outfh.write(chunk)
                        _update(status_queue, task_id, advance=len(chunk))
                    ef.verify()
                    message = "File verified OK!"
                    _info(status_queue, f"{in_path} • {message}")
                    success = True
            except ValueError as e:
                message = f"Error decrypting file: {e}"
                _info(status_queue, f"{in_path} • {message}")
            except VerifyError as e:
                _info(status_queue, f"{in_path} • Verify error: {e}")
                message = "! Verification error, output file should NOT be trusted"
                _info(status_queue, f"{in_path} • {message}")
            except OSError as e:
                message = f"Filesystem error: {e}"
                _info(status_queue, f"{in_path} • {message}")
            except Exception as e:
                message = f"Unknown error: {e}"
                _info(status_queue, f"{in_path} • {message}")

        if not success:
            failed_path = out_path.with_suffix(f"{out_path.suffix}.failed")
            _info(status_queue, f"{in_path} • ! Renaming to {failed_path}")
            out_path.rename(failed_path)
    finally:
        _update(status_queue, task_id, visible=False)
        _exit(status_queue, task_id, str(in_path), message, success)


def _start(queue: Queue, task_id: int) -> None:
    queue.put_nowait((STATUS_START, task_id))


def _update(queue: Queue, task_id: int, *args, **kwargs) -> None:
    queue.put_nowait((STATUS_UPDATE, (task_id, args, kwargs)))


def _info(queue: Queue, msg: str) -> None:
    queue.put_nowait((STATUS_INFO, msg))


def _exit(queue: multiprocessing.Queue, task_id: int, in_path: str, message: str, success: bool) -> None:
    queue.put_nowait((STATUS_EXIT, (task_id, in_path, message, success)))


def setup_logging(logger: logging.Logger, verbosity: int) -> None:
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


def main() -> int:
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

    if args.output and args.output.is_file() and len(args.files) > 1:
        parser.exit("--output should be a directory when decrypting multiple files.")

    files = find_enc_files(args.files)

    if args.output:
        resolv_path = args.output.resolve()
        outputs = [resolv_path / path.stem for path in files] if args.output.is_dir() else [resolv_path]
    else:
        # Strip .enc extension
        outputs = [path.with_suffix("") for path in files]

    if len(set(outputs)) != len(outputs):
        show_duplicates(args.output, files)

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

    exit_code = 0
    ctx = progress or contextlib.nullcontext()
    with ctx:
        signal_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        with multiprocessing.Manager() as mp, ProcessPoolExecutor(max_workers=args.workers) as executor:
            stop_event = mp.Event()
            status_queue = mp.Queue()
            tasks = []

            for in_path, out_path in zip(files, outputs):
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

            results = {}
            while tasks:
                try:
                    cmd, args = status_queue.get(timeout=10)

                    if cmd == STATUS_EXIT:
                        task_id, in_path, message, success = args
                        tasks.remove(task_id)
                        results[in_path] = (success, message)
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
                except (QueueEmptyError, KeyboardInterrupt):  # noqa: PERF203
                    (progress.console.log if progress else log.info)("Stopping...")
                    stop_event.set()
                    executor.shutdown(wait=True, cancel_futures=True)
                    break

            results_string = textwrap.indent(
                "\n".join(
                    f"{file} - {'Success' if success else 'Failed'}: {message}"
                    for file, (success, message) in sorted(results.items())
                ),
                " • ",
            )
            (progress.console.log if progress else log.info)(
                f"\nDecrypt results (file - result: message):\n{results_string}"
            )

            successes = [success for success, _ in results.values()] or [False]
            # If no successful results, return 1
            if not any(successes):
                exit_code = 1
            # Else, if some results but not all were successful return 2
            elif not all(successes):
                exit_code = 2
            # Else, if all were successful but there were still tasks to handle, return 3
            elif tasks:
                exit_code = 3

    return exit_code


def show_duplicates(output_directory: Path, files: list[Path]) -> None:
    # Gather all files that could cause duplicates in `args.output`.
    input_files = defaultdict(list)
    for input_file in files:
        input_files[input_file.name].append(input_file)

    # Find all duplicates
    duplicate_generator = (file_paths for file_paths in input_files.values() if len(file_paths) > 1)
    duplicates = "\n\n".join(
        textwrap.indent(
            "\n".join(str(file) for file in file_paths),
            prefix="  - ",
        )
        for file_paths in duplicate_generator
    )
    log.warning(
        "Two or more encrypted files have the same name. "
        "This will skip decrypting the file if it already exists in '%s'\n"
        "The files with the same names are:\n%s",
        output_directory,
        duplicates,
    )


def find_enc_files(files: list[Path]) -> list[Path]:
    encrypted_files = []
    for path in files:
        if path.is_file() and path.suffix == ".enc":
            encrypted_files.append(path)
        elif path.is_dir():
            encrypted_files.extend(path.rglob("*.enc"))
        else:
            log.info("File %r does not have the .enc extension. skipping", path)
    return encrypted_files


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
