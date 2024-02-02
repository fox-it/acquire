from __future__ import annotations

import time
from argparse import Namespace
from threading import Thread
from typing import Optional


class GUIError(RuntimeError):
    pass


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

    def __new__(cls, flavour: Optional[str] = None, upload_available: bool = False):
        # singleton+factory pattern
        if cls._instance is None:
            cls = Stub
            if str(flavour).lower() == "windows":
                # create a basic Win32 GUI
                from acquire.gui.win32 import Win32

                cls = Win32
            GUI._instance = super(GUI, cls).__new__(cls)
            GUI._instance.upload_available = upload_available
        return GUI._instance

    @classmethod
    def gui(cls) -> GUI:
        """Returns the instance of the GUI."""
        return cls._instance

    @property
    def shard(self) -> int:
        """Returns the shard of the progress bar."""
        return self._shard

    @shard.setter
    def shard(self, shard: int) -> None:
        """Sets the shard of the progress bar."""
        # Use this to 'refine' progress bar (i.e. assign a shard)
        if shard > 100 or shard < 1:
            raise GUIError("Shards have to be between 0-100")
        self._shard = shard

    def wait_for_start(self, args: Namespace) -> tuple[str, bool, bool]:
        """Starts GUI thread and waits for start button to be clicked."""

        def gui_thread() -> None:
            self.show()

        GUI.thread = Thread(target=gui_thread)
        GUI.thread.start()
        while not self.ready and not self._closed:
            time.sleep(1)
        return self.folder, self.auto_upload, self._closed

    def message(self, message: str) -> None:
        """Starts GUI thread and waits for start button to be clicked."""
        raise NotImplementedError

    def wait_for_quit(self) -> None:
        """Closes the GUI and waits for the thread to join."""
        GUI._instance.quit()
        GUI.thread.join()
        self._closed = True

    def show(self) -> None:
        """Subclass needs to implement this."""
        raise NotImplementedError

    def finish(self) -> None:
        """Finishes the progress bar and closes the GUI."""
        raise NotImplementedError


class Stub(GUI):
    """Minimal GUI implementation."""

    def message(self, message: str) -> None:
        pass

    def wait_for_start(self, args: Namespace) -> tuple[str, bool, bool]:
        return args.output, args.auto_upload, False

    def wait_for_quit(self) -> None:
        pass

    def finish(self) -> None:
        pass
