from __future__ import annotations

import time
from ctypes import (
    HRESULT,
    POINTER,
    WINFUNCTYPE,
    Structure,
    WinDLL,
    WinError,
    byref,
    c_int,
    c_int64,
    c_uint,
    c_void_p,
    cast,
    create_string_buffer,
    get_last_error,
    sizeof,
    string_at,
)
from ctypes import wintypes as w
from pathlib import Path
from typing import Any

from acquire.gui import GUI, GUIError


def _winerror(result: int, *args) -> Any:
    if not result:
        raise WinError(get_last_error())
    return result


def LOWORD(dword: w.DWORD) -> w.DWORD:
    return dword & 0x0000FFFF


def HIWORD(dword: w.DWORD) -> w.DWORD:
    return dword >> 16


LRESULT = c_int64
HCURSOR = c_void_p
WNDPROC = WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
BFFCALLBACK = WINFUNCTYPE(c_int, w.HWND, w.UINT, w.LPARAM, w.LPARAM)
CW_USEDEFAULT = -0x80000000
IDI_APPLICATION = w.LPCWSTR(0x7F00)
CS_VREDRAW = 0x0001
CS_HREDRAW = 0x0002
IDC_ARROW = w.LPCWSTR(0x7F00)
WHITE_BRUSH = 0
SW_SHOWNORMAL = 1
WM_DESTROY = 0x0002
WM_ENABLE = 0x000A
WM_PAINT = 0x000F
WM_CLOSE = 0x0010
WM_SETFONT = 0x0030
WM_COMMAND = 0x0111
WM_USER = 0x0400
DT_SINGLELINE = 32
DT_CENTER = 1
DT_VCENTER = 4
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_BORDER = 0x00800000
WS_OVERLAPPEDWINDOW = 0xCF0000
WS_DISABLED = 0x08000000
BS_PUSHBUTTON = 0
BS_CHECKBOX = 2
BS_AUTOCHECKBOX = 3
BS_CENTER = 300
BS_FLAT = 0x8000
ES_PASSWORD = 32
ES_WANTRETURN = 4096
EM_SETPASSWORDCHAR = 204
PBM_SETRANGE = WM_USER + 1
PBM_SETPOS = WM_USER + 2
PBM_DELTAPOS = WM_USER + 3
PBM_SETSTEP = WM_USER + 4
PBM_STEPIT = WM_USER + 5
PBM_SETRANGE32 = WM_USER + 6
PBS_SMOOTH = 0x01
BN_CLICKED = 0
BM_SETCHECK = 241
WM_CTLCOLORSTATIC = 312
SS_LEFT = 0


class WNDCLASSW(Structure):
    _fields_ = (
        ("style", w.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", c_int),
        ("cbWndExtra", c_int),
        ("hInstance", w.HINSTANCE),
        ("hIcon", w.HICON),
        ("hCursor", HCURSOR),
        ("hbrBackground", w.HBRUSH),
        ("lpszMenuName", w.LPCWSTR),
        ("lpszClassName", w.LPCWSTR),
    )


class PAINTSTRUCT(Structure):
    _fields_ = (
        ("hdc", w.HDC),
        ("fErase", w.BOOL),
        ("rcPaint", w.RECT),
        ("fRestore", w.BOOL),
        ("fIncUpdate", w.BOOL),
        ("rgbReserved", w.BYTE * 32),
    )


class INITCOMMONCONTROLSEX(Structure):
    _fields_ = (
        ("dwSize", w.DWORD),
        ("dwICC", w.DWORD),
    )


class BROWSEINFOA(Structure):
    _fields_ = (
        ("hwndOwner", w.HWND),
        ("pidlRoot", w.LPVOID),
        ("pszDisplayName", w.LPSTR),
        ("lpszTitle", w.LPCSTR),
        ("ulFlags", c_uint),
        ("lpfn", BFFCALLBACK),
        ("lParam", w.LPARAM),
        ("iImage", c_int),
    )


class SHITEMID(Structure):
    _fields_ = (
        ("cb", w.USHORT),
        ("abID", w.BYTE),
    )


class ITEMIDLIST(Structure):
    _fields_ = (("mkid", SHITEMID),)


kernel32 = WinDLL("kernel32", use_last_error=True)
kernel32.GetModuleHandleW.argtypes = (w.LPCWSTR,)
kernel32.GetModuleHandleW.restype = w.HMODULE
kernel32.GetModuleHandleW._winerror = _winerror
user32 = WinDLL("user32", use_last_error=True)
user32.CreateWindowExW.argtypes = (
    w.DWORD,
    w.LPCWSTR,
    w.LPCWSTR,
    w.DWORD,
    c_int,
    c_int,
    c_int,
    c_int,
    w.HWND,
    w.HMENU,
    w.HINSTANCE,
    w.LPVOID,
)
user32.CreateWindowExW.restype = w.HWND
user32.CreateWindowExW._winerror = _winerror
user32.SetWindowTextA.argtypes = (
    w.HWND,
    w.LPCSTR,
)
user32.SetWindowTextA.restype = w.BOOL
user32.SetWindowTextA._winerror = _winerror
user32.EnableWindow.argtypes = (
    w.HWND,
    w.BOOL,
)
user32.EnableWindow.restype = w.BOOL
user32.EnableWindow._winerror = _winerror
user32.DestroyWindow.argtypes = (w.HWND,)
user32.DestroyWindow.restype = w.BOOL
user32.DestroyWindow._winerror = _winerror
gdi32 = WinDLL("gdi32", use_last_error=True)
gdi32.GetStockObject.argtypes = (c_int,)
gdi32.GetStockObject.restype = w.HGDIOBJ

gdi32.CreateFontA.argtypes = (
    c_int,
    c_int,
    c_int,
    c_int,
    c_int,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.DWORD,
    w.LPCSTR,
)
gdi32.CreateFontA.restype = w.HFONT

ole32 = WinDLL("ole32", use_last_error=True)
shell32 = WinDLL("shell32", use_last_error=True)
comctl32 = WinDLL("comctl32", use_last_error=True)
comctl32.InitCommonControlsEx.argtypes = (POINTER(INITCOMMONCONTROLSEX),)
comctl32.InitCommonControlsEx.restype = w.BOOL
user32.DefWindowProcW.argtypes = (
    w.HWND,
    w.UINT,
    w.WPARAM,
    w.LPARAM,
)
user32.DefWindowProcW.restype = LRESULT
ole32.CoInitialize.argtypes = (w.LPVOID,)
ole32.CoInitialize.restype = HRESULT
ole32.CoTaskMemFree.argtypes = (w.LPVOID,)
ole32.CoTaskMemFree.restype = None
shell32.SHBrowseForFolderA.argtypes = (POINTER(BROWSEINFOA),)
shell32.SHBrowseForFolderA.restype = POINTER(ITEMIDLIST)
shell32.SHBrowseForFolderA._winerror = _winerror
shell32.SHGetPathFromIDList.argtypes = (POINTER(ITEMIDLIST), w.LPCSTR)
shell32.SHGetPathFromIDList.restype = w.BOOL
shell32.SHGetPathFromIDList._winerror = _winerror
SendMessage = user32.SendMessageA
SendMessage.argtypes = (w.HWND, w.UINT, w.WPARAM, w.LPARAM)
SendMessage.restype = c_void_p
user32.MessageBoxA.argtypes = (
    w.HWND,
    w.LPCSTR,
    w.LPCSTR,
    c_uint,
)
user32.MessageBoxA.restype = c_int
user32.MessageBoxA._winerror = _winerror


class Win32(GUI):
    result = ""
    pass_shown = False
    gui_display_text = ""

    start_button = None
    choose_folder_button = None

    input_field = None
    checkbox = None
    reveal_text = None
    label = None
    info = None
    upload_label = None
    progress_bar = None
    image = None

    hwnd = None
    quitting = False

    @property
    def progress(self) -> int:
        return self._progress

    @progress.setter
    def progress(self, progress: int) -> None:
        if self._closed:
            return

        if self._progress > progress:
            return

        self._progress = progress
        SendMessage(self._instance.progress_bar, PBM_SETPOS, int(self._progress), 0)

    def quit(self) -> None:
        if self._closed:
            return
        self.quitting = True
        user32.DestroyWindow(self.hwnd)

    def finish(self) -> None:
        if self._closed:
            return
        self.progress = 100
        time.sleep(1)  # give user some time to observe 100%
        self.message("Operation complete, application will close now.")

    def message(self, message: str) -> None:
        if self._closed:
            return
        user32.MessageBoxA(self.hwnd, message.encode("ascii"), b"Acquire", 0x00040000)

    def choose_folder(self) -> None:
        if self._closed:
            return

        browseinfo = BROWSEINFOA()
        browseinfo.hwndOwner = self.hwnd
        browseinfo.pidlRoot = None
        browseinfo.pszDisplayName = cast(create_string_buffer(b"", size=1000), w.LPSTR)
        browseinfo.lpszTitle = cast(create_string_buffer(b"Acquire"), w.LPCSTR)
        browseinfo.ulFlags = 0
        browseinfo.lpfn = BFFCALLBACK(_bffcallback)
        browseinfo.lParam = 0
        browseinfo.iImage = 0
        choice = shell32.SHBrowseForFolderA(byref(browseinfo))
        path = create_string_buffer(b"", size=1000)
        shell32.SHGetPathFromIDList(choice, path)
        pathstr = string_at(path).decode("utf-8")
        if pathstr:
            self.folder = Path(pathstr)
            user32.SetWindowTextA(self.label, string_at(path))
            user32.EnableWindow(self.start_button, True)

        # Caller is responsible for freeing this memory.
        ole32.CoTaskMemFree(choice)

    def show(self) -> None:
        if self._closed:
            return

        wndclass = WNDCLASSW()
        wndclass.style = CS_HREDRAW | CS_VREDRAW
        wndclass.lpfnWndProc = WNDPROC(_winmessage)
        wndclass.cbClsExtra = wndclass.cbWndExtra = 0
        wndclass.hInstance = kernel32.GetModuleHandleW(None)
        wndclass.hIcon = user32.LoadIconW(None, IDI_APPLICATION)
        wndclass.hCursor = user32.LoadCursorW(None, IDC_ARROW)
        wndclass.hbrBackground = gdi32.GetStockObject(WHITE_BRUSH)
        wndclass.lpszMenuName = None
        wndclass.lpszClassName = "AcquireGUI"
        user32.RegisterClassW(byref(wndclass))
        hwnd = user32.CreateWindowExW(
            0,
            wndclass.lpszClassName,
            "Acquire",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            600,
            400,
            None,
            None,
            wndclass.hInstance,
            None,
        )

        user32.ShowWindow(hwnd, SW_SHOWNORMAL)
        user32.UpdateWindow(hwnd)
        ole32.CoInitialize(None)
        control_list = INITCOMMONCONTROLSEX()
        control_list.dwSize = sizeof(INITCOMMONCONTROLSEX)
        control_list.dwICC = 0x00000020
        controls_loaded = comctl32.InitCommonControlsEx(byref(control_list))

        if not controls_loaded:
            raise GUIError("Unable to load GUI controls")

        hFont = gdi32.CreateFontA(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b"Segoe UI")

        if self.upload_available:
            self.checkbox = user32.CreateWindowExW(
                0, "Button", None, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 250, 16, 16, hwnd, 0, 0, 0
            )
            self.upload_label = user32.CreateWindowExW(
                0, "static", "Upload", WS_CHILD | WS_VISIBLE | SS_LEFT, 50, 250, 100, 32, hwnd, 0, 0, 0
            )
            if hFont:
                SendMessage(self.upload_label, WM_SETFONT, hFont, 1)
            GUI.auto_upload = True
            SendMessage(self.checkbox, BM_SETCHECK, 1, 0)

        self.progress_bar = user32.CreateWindowExW(
            0,
            "msctls_progress32",
            None,
            WS_CHILD | WS_VISIBLE | WS_BORDER | PBS_SMOOTH,
            20,
            300,
            550,
            32,
            hwnd,
            0,
            0,
            0,
        )

        self.info = user32.CreateWindowExW(
            0, "static", "Acquire output folder:", WS_CHILD | WS_VISIBLE, 20, 20, 200, 20, hwnd, 0, 0, 0
        )
        self.label = user32.CreateWindowExW(
            0, "static", "No path selected...", WS_CHILD | WS_VISIBLE, 20, 40, 400, 25, hwnd, 0, 0, 0
        )
        self.choose_folder_button = user32.CreateWindowExW(
            0, "Button", "Choose folder", WS_CHILD | WS_VISIBLE | WS_BORDER | BS_FLAT, 450, 35, 120, 32, hwnd, 0, 0, 0
        )
        self.start_button = user32.CreateWindowExW(
            0,
            "Button",
            "Start",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_DISABLED | BS_FLAT,
            250,
            100,
            100,
            32,
            hwnd,
            0,
            0,
            0,
        )
        if hFont:
            SendMessage(self.info, WM_SETFONT, hFont, 1)
            SendMessage(self.start_button, WM_SETFONT, hFont, 1)
            SendMessage(self.choose_folder_button, WM_SETFONT, hFont, 1)
            SendMessage(self.label, WM_SETFONT, hFont, 1)

        msg = w.MSG()
        while user32.GetMessageW(byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(byref(msg))
            user32.DispatchMessageW(byref(msg))
            if self.quitting:
                break

    def _message(self, hwnd: w.HWND, message: w.UINT, wParam: w.WPARAM, lParam: w.LPARAM) -> w.LRESULT:
        if message == WM_COMMAND:
            if lParam == self.choose_folder_button:
                event = HIWORD(wParam)
                if event == BN_CLICKED:
                    self.choose_folder()
            elif lParam == self.start_button:
                user32.EnableWindow(self.start_button, False)
                user32.EnableWindow(self.choose_folder_button, False)
                if self.checkbox:
                    user32.EnableWindow(self.checkbox, False)
                self.ready = True
                self.progress = 1  # make it visible to the user that we are starting
            elif lParam == self.checkbox:
                self.auto_upload = not self.auto_upload
            return 0
        if message == WM_CLOSE:
            if self.ready:
                user32.MessageBoxA(hwnd, b"We are in the middle of acquiring this host, please wait.", b"Acquire", 0)
                return 0
            answer = user32.MessageBoxA(hwnd, b"Are you sure you want to quit?", b"Acquire", 0x01 | 0x030)
            if answer == 1:
                self._closed = True
                user32.DestroyWindow(hwnd)
            return 0

        if message == WM_CTLCOLORSTATIC and lParam in [self.upload_label, self.info]:
            return gdi32.GetStockObject(WHITE_BRUSH)

        if message == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, message, wParam, lParam)


# Just keep this for the function signature
def _bffcallback(hwnd: w.HWND, message: w.UINT, lParam: w.LPARAM, lpData: w.LPARAM) -> c_int:
    return 0


# Just keep this for the function signature
def _winmessage(hwnd: w.HWND, message: w.UINT, wParam: w.WPARAM, lParam: w.LPARAM) -> w.LRESULT:
    return GUI._instance._message(hwnd, message, wParam, lParam)
