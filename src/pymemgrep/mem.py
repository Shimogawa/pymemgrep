from typing import Union, Optional
import ctypes as _ctypes
from struct import unpack as _unpack
from struct import calcsize as _calcsize
from inspect import getmodule as _getmodule
import psutil as _psutil

from . import types as _types

if _types.IS_WIN:
    from . import _nt as _nt


def get_process(name: str) -> Optional[_psutil.Process]:
    for proc in _psutil.process_iter():
        if name in proc.name():
            return proc
    return None


def get_pid(name: str) -> int:
    p = get_process(name)
    if p is None:
        raise ValueError("Process can not be found.")
    return p.pid


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


def _make_read_mem_func(t, tcode, ret_type):
    def f(proc_handle: _types.HANDLE, base_addr: int):
        bs = read_mem(proc_handle, base_addr, _calcsize(tcode))
        return _unpack(tcode, bs)[0]
    f.__annotations__["return"] = ret_type
    f.__name__ = f"read_mem_{t}"
    return f

_cur_module = _getmodule(read_mem)


for t, (tcode, ret_type) in _NATIVE_TYPES.items():
    setattr(_cur_module, f"read_mem_{t}", _make_read_mem_func(t, tcode, ret_type))
