"""Per-object code and static-data sizes from the linker map of the benchmark firmware.

    python3 analysis/code_size.py firmware/.pio/build/esp32dev/firmware.map results/raw/code_size_members.csv

Only sections that survived --gc-sections are in the memory map part of the file, so these are bytes that
really sit in the image. 'code' is .flash.text + .iram0.text (including literal pools), 'rodata' is
.flash.rodata, 'data' is .dram0.data + .dram0.bss.
"""
import csv, re, sys
from collections import defaultdict

CLASS = {'.flash.text': 'code', '.iram0.text': 'code', '.flash.rodata': 'rodata',
         '.dram0.data': 'data', '.dram0.bss': 'data'}


def group_of(path):
    m = re.search(r'/pqclean/([^/]+)/([^/]+)$', path)
    if m: return 'pqclean/' + m.group(1), m.group(2)
    m = re.search(r'/(lib[a-z0-9_]+)\.a\(([^)]+)\)$', path)
    if m and m.group(1) in ('libmbedcrypto', 'liblibsodium', 'libmbedtls'): return m.group(1), m.group(2)
    return None, None


def main(mapfile, out):
    sizes = defaultdict(int)
    in_map = False; cur = None; pending = None
    num = re.compile(r'^\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+(\S.*)$')
    one = re.compile(r'^ (\S+)\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+(\S.*)$')
    for ln in open(mapfile, errors='replace'):
        if not in_map:
            in_map = ln.startswith('Linker script and memory map'); continue
        if ln[0] == '.':
            cur = ln.split()[0]; pending = None; continue
        if cur not in CLASS: continue
        m = one.match(ln)
        if m: name, sz, path = m.groups()
        else:
            m = re.match(r'^ (\S+)\s*$', ln)
            if m: pending = m.group(1); continue
            m = num.match(ln)
            if not (m and pending): continue
            sz, path = m.groups()
        pending = None
        sz = int(sz, 16)
        g, member = group_of(path.strip())
        if g and sz: sizes[(g, member, CLASS[cur])] += sz
    with open(out, 'w', newline='') as f:
        w = csv.writer(f); w.writerow(['group', 'member', 'class', 'bytes'])
        for (g, mem, c), n in sorted(sizes.items()): w.writerow([g, mem, c, n])


if __name__ == '__main__':
    main(*sys.argv[1:3])
