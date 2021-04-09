import sys
sys.path.append("src")

import pymemgrep.scan as scan

scanner = scan.MemScanner("QQ.exe")
rlist = scanner.region_list
print(rlist[0].dumped_region[:])
