import sys
sys.path.append("src")

from pymemgrep import mem, MemScanner

scanner = MemScanner("QQ.exe")
base = scanner.region_list[0].base_address.value

print("10 bytes:", scanner.region_list[0].dumped_region[:10])
print("10 bytes:", mem.read_mem(scanner._handle, base, 10))

for i in mem._NATIVE_TYPES:
    print(f"{i}:", getattr(mem, f"read_mem_{i}")(scanner._handle, base))
