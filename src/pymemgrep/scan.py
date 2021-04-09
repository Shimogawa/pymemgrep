import ctypes as _ctypes
from typing import Any, List, Union, Optional

from .types import *
from . import _nt as _nt
from . import mem as _mem


__all__ = ["MemoryRegion", "MemScanner"]


class MemoryRegion:
    def __init__(
        self, allocation_base: LPVOID, base_address: LPVOID, region_size: SIZE_T
    ):
        self.allocation_base: LPVOID = allocation_base
        self.base_address: LPVOID = base_address
        self.region_size: SIZE_T = region_size
        self.dumped_region: Optional[_ctypes.Array] = None

    def __str__(self):
        return "%s(%s)" % (
            type(self).__name__,
            ", ".join("%s=%s" % item for item in vars(self).items()),
        )

    def __repr__(self):
        return self.__str__()


def _check_mask(memory: _ctypes.Array, offset: int, pattern: bytes, mask: str) -> bool:
    if offset + len(pattern) > len(memory):
        return False
    for i in range(len(pattern)):
        if mask[i] == "?":
            continue
        if pattern[i] != memory[offset + i]:
            return False
    return True


class MemScanner:
    def __init__(self, process: Union[int, str]):
        self._region_list: List[MemoryRegion] = []
        if process == 0:
            raise RuntimeError("Invalid handle.")
        self._pid: int = process if isinstance(process, int) else _mem.get_pid(process)
        self._handle = _nt.open_process(self._pid)
        self._sysinfo = _nt.SYSINFO
        self._init_region_list()

    def _init_region_list(self) -> None:
        handle = _nt.open_process(self._pid)
        current_addr: int = _nt.SYSINFO.MinimumApplicationAddress
        proc_max_addr: int = _nt.SYSINFO.MaximumApplicationAddress
        while current_addr < proc_max_addr:
            mem_info = _nt.query_mem_info(handle, LPCVOID(current_addr))
            if (
                mem_info.Protect & _nt.AllocationProtect.PAGE_EXECUTE_READWRITE > 0
                and mem_info.State == _nt.MEM_COMMIT
            ):
                region = MemoryRegion(
                    LPVOID(mem_info.AllocationBase),
                    LPVOID(mem_info.BaseAddress),
                    SIZE_T(mem_info.RegionSize),
                )
                self._region_list.append(region)
            current_addr += mem_info.RegionSize
        _nt.close_handle(handle)

    def _dump_memory(self) -> bool:
        for region in self._region_list:
            if region.dumped_region is None:
                region.dumped_region = _ctypes.create_string_buffer(
                    region.region_size.value
                )
            read_size = _nt.read_proc_mem(
                self._handle,
                region.base_address,
                region.dumped_region,
                region.region_size,
            )
            if read_size.value != region.region_size.value:
                return False
        return True

    def search_pattern(
        self, pattern: Union[str, bytes], mask: Optional[str] = None
    ) -> int:
        """
        Searches for the pattern in the memory of the process.

        Parameters
        ----------
        pattern:
            If given as a string, the format will be like
                5A 0F 3C ?? 5D 9A 4B
            where ?? matches any byte and space can be omitted.
            If given as a byte array, the format will be like
                \\x5a\\x0f\\x3c\\x00\\x5d\\x9a\\x4b
            and if wildcard is needed, you should use the `mask` parameter.

        mask:
            If given, then the format will be like
                xxx?xxx
            where ? is the position of the byte to match any byte.

        Returns
        -------
        The starting location of the matched memory section. If not found, then 0 is returned.
        """
        if isinstance(pattern, str):
            pattern = pattern.replace(" ", "")
            if mask is None:
                mask = ""
                for i in range(0, len(pattern), 2):
                    mask += "?" if pattern[i : i + 2] == "??" else "x"
            pattern = pattern.replace("??", "00")
            pattern = bytes.fromhex(pattern)
        if not self._dump_memory():
            return 0
        assert mask is not None
        for region in self._region_list:
            assert region.dumped_region is not None
            assert region.base_address.value is not None
            for i in range(len(region.dumped_region)):
                if _check_mask(region.dumped_region, i, pattern, mask):
                    return region.base_address.value + i
        return 0

    def read_mem(self, base_addr: int, size: int) -> bytes:
        return _mem.read_mem(self._handle, base_addr, size)

    @property
    def region_list(self) -> List[MemoryRegion]:
        if not self._dump_memory():
            raise RuntimeError("Unable to dump memory")
        return self._region_list

    def close(self) -> None:
        _nt.close_handle(self._handle)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return
