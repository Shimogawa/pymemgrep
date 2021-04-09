from typing import Union
import ctypes as _ctypes
from struct import unpack as _unpack
from struct import calcsize as _calcsize
from inspect import getmodule as _getmodule

from . import _nt as _nt
from . import types as _types


def get_pid(proc_name: str) -> int:
    pid = _nt.get_pid(proc_name)
    if pid is None:
        raise ValueError("Process can not be found.")
    return pid


def get_handle(proc: Union[int, str]) -> _types.HANDLE:
    return _nt.open_process(proc if isinstance(proc, int) else get_pid(proc))


def read_mem(proc_handle: _types.HANDLE, base_addr: int, size: int) -> bytes:
    buffer = _ctypes.create_string_buffer(size)
    if _nt.read_proc_mem(proc_handle, _types.LPCVOID(base_addr), buffer, _types.SIZE_T(size)).value != size:
        print(size)
        raise RuntimeError("Unable to read memory. Maybe caused by bad arguments.")
    return buffer.raw


_NATIVE_TYPES = {
    "bool": ("?", bool),
    "byte": ("b", int),
    "sbyte": ("b", int),
    "ubyte": ("B", int),
    "short": ("h", int),
    "ushort": ("H", int),
    "int": ("i", int),
    "uint": ("I", int),
    "long": ("l", int),
    "ulong": ("L", int),
    "ll": ("q", int),
    "ull": ("Q", int),
    "ssizet": ("n", int),
    "sizet": ("N", int),
    "float": ("f", float),
    "double": ("d", float),
}

_cur_module = _getmodule(read_mem)


def _make_read_mem_func(t, tcode, ret_type):
    def f(proc_handle: _types.HANDLE, base_addr: int):
        bs = read_mem(proc_handle, base_addr, _calcsize(tcode))
        return _unpack(tcode, bs)[0]
    f.__annotations__["return"] = ret_type
    f.__name__ = f"read_mem_{t}"
    return f


for t, (tcode, ret_type) in _NATIVE_TYPES.items():
    setattr(_cur_module, f"read_mem_{t}", _make_read_mem_func(t, tcode, ret_type))
