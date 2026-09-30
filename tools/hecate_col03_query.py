"""ON/OFF comparison probe for GX03 COL03: write d0 35 bb 01 and dump FULL
responses, to verify the response encodes current link/battery state.

Usage: python hecate_col03_query.py [rounds] [gap_seconds]
"""
import sys
import time
import hid

VID, PID = 0x35BB, 0xA217


def find_col03():
    for d in hid.enumerate(VID, PID):
        if d['interface_number'] == 4 and d['usage_page'] == 0xFF02 and b'Col03' in d['path']:
            return d['path']
    return None


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    gap = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    path = find_col03()
    if not path:
        print('COL03 not found')
        return
    h = hid.device()
    h.open_path(path)
    print('opened COL03')
    try:
        while h.read(64, timeout_ms=200):
            pass
        for i in range(rounds):
            n = h.write(bytes([0xD0, 0x35, 0xBB, 0x01]) + bytes(60))
            print(f'--- round {i}: wrote {n} bytes [d0 35 bb 01]')
            deadline = time.time() + gap
            while time.time() < deadline:
                data = h.read(64, timeout_ms=300)
                if data:
                    print('  RSP ' + bytes(data[:16]).hex(' '), flush=True)
            time.sleep(1.0)
    finally:
        h.close()


if __name__ == '__main__':
    main()
