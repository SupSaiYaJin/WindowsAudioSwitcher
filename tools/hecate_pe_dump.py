"""Dump PE exports and printable strings from the HECATE vendor DLLs to
reconstruct the dongle HID protocol. Read-only analysis tool.

Usage: python hecate_pe_dump.py <dll-or-exe> [strings|min-words]
"""
import re
import sys

import pefile


def exports(path):
    pe = pefile.PE(path)
    print(f'== {path} ==')
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f'ord{exp.ordinal}'
            print(f'  {name}')
    else:
        print('  (no exports)')


def strings(path, min_len=5):
    pe = pefile.PE(path)
    data = pe.__data__
    pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    for m in pat.finditer(data):
        print(m.group().decode())


def imports(path):
    pe = pefile.PE(path)
    print(f'== {path} imports ==')
    for imp in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        dll = imp.dll.decode()
        names = [i.name.decode() for i in imp.imports if i.name]
        interesting = [n for n in names if any(
            k in n for k in ('DeviceIo', 'HidD', 'Write', 'Read', 'CreateFile'))]
        if interesting:
            print(f'  {dll}: {", ".join(interesting)}')


if __name__ == '__main__':
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'exports'
    if mode == 'exports':
        exports(path)
    elif mode == 'imports':
        imports(path)
    else:
        strings(path, int(mode) if mode.isdigit() else 5)
