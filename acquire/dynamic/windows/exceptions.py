class WindowsDynamicError(Exception):
    pass


class AccessDeniedError(WindowsDynamicError):
    pass


class NoMoreEntriesError(WindowsDynamicError):
    pass


class HandleNotClosedSuccessfullyError(WindowsDynamicError):
    pass


class OpenProcessError(WindowsDynamicError):
    pass
