from __future__ import annotations

import logging
import time
from threading import Thread

log = logging.getLogger("gui")


class GUI:
    _instance = None
    _progress = 0
    _closed = False
    _shard = 0

    thread = None
    folder = None
    ready = False
    auto_upload = None
    upload_available = False

    @classmethod
    def gui(cls):
        """Returns the instance of the GUI"""
        return cls._instance

    @property
    def shard(self):
        """Returns the shard of the progress bar"""
        return self._shard

    @shard.setter
    def shard(self, shard: int) -> None:
        """Sets the shard of the progress bar"""
        # Use this to 'refine' progress bar (i.e. assign a shard)
        if shard > 100 or shard < 1:
            raise ValueError("Shards have to be between 0-100")
        self._shard = shard

    def __new__(cls, flavour=None, upload_available=False):
        # singleton+factory pattern
        if cls._instance is None:
            if flavour == "Windows":
                # create a basic Win32 GUI
                from acquire.guis.wingui import WinGUI

                cls = WinGUI
                log.info("Creating win32 gui instance")
            else:
                # Use the NULL-pattern here, to avoid many IFs
                cls = StubGUI
                log.info("Creating stub gui instance")

            if flavour is None:
                log.warning("GUI has been initialised with invalid flavour, possible logic flaw.")

            GUI._instance = super(GUI, cls).__new__(cls)
            GUI._instance.upload_available = upload_available
        return GUI._instance

    def wait_for_start(self, args) -> (str, bool, bool):
        """Starts GUI thread and waits for start button to be clicked."""
        log.info("Opening GUI window and starting GUI thread...")

        def guit():
            self.show()

        GUI.thread = Thread(target=guit)
        GUI.thread.start()
        while not self.ready and not self._closed:
            time.sleep(1)
        return self.folder, self.auto_upload, self._closed

    def message(message: str) -> None:
        """Starts GUI thread and waits for start button to be clicked."""
        raise NotImplementedError

    def wait_for_quit(self) -> None:
        """Closes the GUI and waits for the thread to join."""
        log.info("Closing GUI windows and joining GUI thread...")
        GUI._instance.quit()
        GUI.thread.join()
        self._closed = True

    def show(self, args):
        raise NotImplementedError


class StubGUI(GUI):
    """Minimal GUI implementation."""

    def message(message: str):
        pass

    def wait_for_start(self, args) -> (str, bool, bool):
        return args.output, args.auto_upload, args.cancel

    def wait_for_quit(self) -> None:
        pass