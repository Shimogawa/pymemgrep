import sys
sys.path.append("src")

import pymemgrep._nt as nt
import pymemgrep.mem as mem
import ctypes

# osu = nt.open_process("osu!.exe")
# print(osu)
# print(nt.close_handle(osu))

sysinfo = nt.SYSINFO
# print(hex(sysinfo.MinimumApplicationAddress))
# print(hex(sysinfo.MaximumApplicationAddress))

handle = nt.open_process(mem.get_pid("Code.exe"))
addr = sysinfo.MinimumApplicationAddress
while True:
    meminfo = nt.query_mem_info(handle, addr)
    if meminfo.Protect & nt.AllocationProtect.PAGE_EXECUTE_READWRITE > 0 and meminfo.State == nt.MEM_COMMIT:
        break
    addr += meminfo.RegionSize

print(hex(meminfo.BaseAddress))
print(hex(meminfo.RegionSize))

buffer = ctypes.create_string_buffer(meminfo.RegionSize)
# buffer = (ctypes.c_char * meminfo.RegionSize)()

# print(type(buffer))

num_b_read = nt.read_proc_mem(handle, nt.LPCVOID(meminfo.BaseAddress), buffer, nt.SIZE_T(meminfo.RegionSize))

print(num_b_read)
print(buffer[:300])
