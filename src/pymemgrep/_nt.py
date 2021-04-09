import ctypes
import psutil
import struct
from typing import Optional, Union, Tuple, Any
from enum import IntFlag

from .types import *


IS_X64 = struct.calcsize("P") == 8

_kernel32 = ctypes.windll.kernel32

PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04
PROCESS_VM_READ = 0x0010


class AllocationProtect(IntFlag):
    PAGE_EXECUTE = 0x00000010
    PAGE_EXECUTE_READ = 0x00000020
    PAGE_EXECUTE_READWRITE = 0x00000040
    PAGE_EXECUTE_WRITECOPY = 0x00000080
    PAGE_NOACCESS = 0x00000001
    PAGE_READONLY = 0x00000002
    PAGE_READWRITE = 0x00000004
    PAGE_WRITECOPY = 0x00000008
    PAGE_GUARD = 0x00000100
    PAGE_NOCACHE = 0x00000200
    PAGE_WRITECOMBINE = 0x00000400


# typedef struct _MEMORY_BASIC_INFORMATION32 {
#     DWORD BaseAddress;
#     DWORD AllocationBase;
#     DWORD AllocationProtect;
#     DWORD RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;
class MEMORY_BASIC_INFORMATION_X86(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


# typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64 {
#     ULONGLONG BaseAddress;
#     ULONGLONG AllocationBase;
#     DWORD     AllocationProtect;
#     DWORD     __alignment1;
#     ULONGLONG RegionSize;
#     DWORD     State;
#     DWORD     Protect;
#     DWORD     Type;
#     DWORD     __alignment2;
# } MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;
class MEMORY_BASIC_INFORMATION_X64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", ULONGLONG),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD),
    ]


def get_process(name: str) -> Optional[psutil.Process]:
    for proc in psutil.process_iter():
        if proc.name() == name:
            return proc
    return None


def get_pid(name: str) -> Optional[int]:
    p = get_process(name)
    if p is None:
        return None
    return p.pid


def open_process(pid: int) -> HANDLE:
    if not isinstance(pid, int) or pid <= 0:
        raise RuntimeError("Invalid pid")
    # HANDLE OpenProcess(
    #     DWORD dwDesiredAccess,
    #     BOOL  bInheritHandle,
    #     DWORD dwProcessId
    # );
    hnd = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if hnd == 0:
        raise RuntimeError(f"Failed to open process {pid}.")
    return HANDLE(hnd)


def close_handle(handle: HANDLE) -> bool:
    return bool(_kernel32.CloseHandle(handle))


def query_mem_info(
    process_handle: HANDLE, addr_start: LPCVOID
) -> Union[MEMORY_BASIC_INFORMATION_X64, MEMORY_BASIC_INFORMATION_X86]:
    mem_info: Union[MEMORY_BASIC_INFORMATION_X64, MEMORY_BASIC_INFORMATION_X86] = (
        MEMORY_BASIC_INFORMATION_X64() if IS_X64 else MEMORY_BASIC_INFORMATION_X86()
    )
    mem_info_size: int = ctypes.sizeof(mem_info)
    # SIZE_T VirtualQueryEx(
    #   HANDLE                    hProcess,
    #   LPCVOID                   lpAddress,
    #   PMEMORY_BASIC_INFORMATION lpBuffer,
    #   SIZE_T                    dwLength
    # );
    if (
        _kernel32.VirtualQueryEx(process_handle, addr_start, ctypes.pointer(mem_info), mem_info_size)
        != mem_info_size
    ):
        raise RuntimeError("System error.")

    return mem_info


# BOOL ReadProcessMemory(
#   HANDLE  hProcess,
#   LPCVOID lpBaseAddress,
#   LPVOID  lpBuffer,
#   SIZE_T  nSize,
#   SIZE_T  *lpNumberOfBytesRead
# );
def read_proc_mem(
    hproc: HANDLE, base_addr: LPCVOID, buffer: Any, size: SIZE_T
) -> SIZE_T:
    num_read = SIZE_T(0)
    res = _kernel32.ReadProcessMemory(hproc, base_addr, buffer, size, ctypes.byref(num_read))
    if not res:
        raise ctypes.WinError()
    return num_read


# typedef struct _SYSTEM_INFO {
#   union {
#     DWORD dwOemId;
#     struct {
#       WORD wProcessorArchitecture;
#       WORD wReserved;
#     } DUMMYSTRUCTNAME;
#   } DUMMYUNIONNAME;
#   DWORD     dwPageSize;
#   LPVOID    lpMinimumApplicationAddress;
#   LPVOID    lpMaximumApplicationAddress;
#   DWORD_PTR dwActiveProcessorMask;
#   DWORD     dwNumberOfProcessors;
#   DWORD     dwProcessorType;
#   DWORD     dwAllocationGranularity;
#   WORD      wProcessorLevel;
#   WORD      wProcessorRevision;
# } SYSTEM_INFO, *LPSYSTEM_INFO;
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("ProcessorArchitecture", WORD),
        ("__reserved1", WORD),
        ("PageSize", DWORD),
        ("MinimumApplicationAddress", LPVOID),
        ("MaximumApplicationAddress", LPVOID),
        ("ActiveProcessorMask", ctypes.POINTER(DWORD)),
        ("NumberOfProcessors", DWORD),
        ("ProcessorType", DWORD),
        ("AllocationGranularity", DWORD),
        ("ProcessorLevel", WORD),
        ("ProcessorRevision", WORD),
    ]


def _get_sys_info() -> SYSTEM_INFO:
    sysinfo = SYSTEM_INFO()
    _kernel32.GetSystemInfo(ctypes.pointer(sysinfo))
    return sysinfo


SYSINFO = _get_sys_info()
