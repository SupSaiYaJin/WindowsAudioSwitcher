"""Probe MI_04&COL03 of the GX03 dongle with candidate query frames.

The dongle pushes status on COL03 (report id 0xD0, magic 35 BB, cmd 0x01 =
link up/down). The vendor app never writes, so a query command is unknown.
This script writes a few low-risk candidate frames (echoing observed report
formats) and logs any response. Run once with headset ON, once OFF.

Usage: python hecate_col03_probe.py [seconds_between_candidates]
"""
import sys
import time
import hid

VID, PID = 0x35BB, 0xA217
COL3_PAGE = 0xFF02


def find_col03():
    for d in hid.enumerate(VID, PID):
        # COL03 = MI_04, second vendor collection; distinguish by usage page + path col index
        if d['interface_number'] == 4 and d['usage_page'] == COL3_PAGE and b'Col03' in d['path']:
            return d['path']
    return None


def main():
    gap = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    path = find_col03()
    if not path:
        print('COL03 not found')
        return
    h = hid.device()
    h.open_path(path)
    print('opened COL03')
    try:
        # drain
        while h.read(64, timeout_ms=100):
            pass
        candidates = [
            ('d0-mirror-link', [0xD0, 0x35, 0xBB, 0x01]),
            ('d0-mirror-link-01', [0xD0, 0x35, 0xBB, 0x01, 0x01]),
            ('d0-battery-get', [0xD0, 0x35, 0xBB, 0x05]),
            ('d0-version-get', [0xD0, 0x35, 0xBB, 0x09]),
            ('rep02', [0x02, 0x35, 0xBB, 0x01]),
            ('rep41', [0x41, 0x35, 0xBB, 0x01]),
        ]
        for name, frame in candidates:
            buf = bytes(frame) + bytes(64 - len(frame))
            try:
                n = h.write(buf)
            except Exception as e:
                print(f'  {name}: write FAILED {e}')
                continue
            deadline = time.time() + gap
            resp = []
            while time.time() < deadline:
                data = h.read(64, timeout_ms=200)
                if data:
                    resp.append(bytes(data[:12]).hex(' '))
            print(f'  {name}: write={n} responses={resp if resp else "none"}', flush=True)
        # passive tail
        deadline = time.time() + gap * 2
        print('passive tail ...')
        while time.time() < deadline:
            data = h.read(64, timeout_ms=300)
            if data:
                print('  PUSH ' + bytes(data[:12]).hex(' '), flush=True)
    finally:
        h.close()


if __name__ == '__main__':
    main()
