import ctypes as _ctypes
from typing import Any
import struct as _struct
import os as _os

HANDLE = _ctypes.c_void_p
ULONGLONG = _ctypes.c_ulonglong
DWORD = _ctypes.c_ulong
WORD = _ctypes.c_ushort
LPCVOID = _ctypes.c_void_p
LPVOID = _ctypes.c_void_p
PVOID = _ctypes.c_void_p
SIZE_T = _ctypes.c_size_t

NULL = _ctypes.c_void_p(0)

IS_X64 = _struct.calcsize("P") == 8
IS_WIN = _os.name == "nt"


def is_null(ptr: Any) -> bool:
    """
    Tests if a value represents the null pointer.
    """
    if ptr is None:
        return True
    if isinstance(ptr, int):
        return ptr == 0
    if getattr(ptr, "value", False):
        return ptr.value == 0
    return False

