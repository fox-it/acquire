import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

STREAM_FORMATTER = logging.Formatter("%(message)s")
FILE_FORMATTER = logging.Formatter("[%(asctime)s] [%(levelname)-5s] %(message)s")


class DelayedFileHandler(logging.FileHandler):
    def __init__(self, filename, *args, **kwargs):
        self.opened = False
        self._record_cache = []

        kwargs["delay"] = True
        logging.FileHandler.__init__(self, filename, *args, **kwargs)

    def set_filename(self, filename):
        if not self.opened:
            base_dir = os.path.dirname(self.baseFilename)
            self.baseFilename = os.fspath(os.path.join(base_dir, filename))
            self.flush_cache()
            self.opened = True

    def set_stream(self, stream):
        if not self.opened:
            self.stream = stream
            self.flush_cache()
            self.opened = True

    def flush_cache(self):
        if self._record_cache:
            for record in self._record_cache:
                logging.FileHandler.emit(self, record)
            self._record_cache = []

    def emit(self, record):
        if not self.opened:
            self._record_cache.append(record)
        else:
            logging.FileHandler.emit(self, record)

    def close(self):
        if not self.opened:
            # Close without being opened? Something probably broke
            if Path(self.baseFilename).parent.exists():
                log.info("Log written to file %s", Path(self.baseFilename).resolve())
                self.set_filename(self.baseFilename)
        logging.FileHandler.close(self)


def setup_logging(logger, path, verbosity, delay=False):
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
    stream_handler.setFormatter(STREAM_FORMATTER)
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)

    if path:
        file_handler = new_file_handler(path, delay)
        logger.addHandler(file_handler)

        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)


def reconfigure_log_file(logger, path, delay=False):
    file_handler = get_file_handler(logger)
    if file_handler is None:
        return

    # File handler is already opened, so close it and configure a new one
    if file_handler.stream:
        logger.removeHandler(file_handler)

        root_logger = logging.getLogger()
        root_logger.removeHandler(file_handler)

        file_handler.close()

        file_handler = new_file_handler(path, delay)
        logger.addHandler(file_handler)
        root_logger.addHandler(file_handler)
    else:
        file_handler.baseFilename = os.fspath(path)


def new_file_handler(path, delay=False):
    file_handler = DelayedFileHandler(path) if delay else logging.FileHandler(path)
    file_handler.setFormatter(FILE_FORMATTER)
    file_handler.setLevel(logging.DEBUG)
    return file_handler


def get_file_handler(logger):
    try:
        return next(handler for handler in logger.handlers if isinstance(handler, logging.FileHandler))
    except StopIteration:
        return None
