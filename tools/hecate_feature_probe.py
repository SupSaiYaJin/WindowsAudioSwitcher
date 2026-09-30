"""Blind feature/input report probe for the HECATE GX03 Ultra dongle.

For every vendor collection (usage_page 0xFF02) plus the telephony collection:
  1. drain input reports
  2. try HidD-style get_feature_report for report ids 0x00..0x10
  3. dump whatever answers, hex + printable

Usage: python hecate_feature_probe.py [seconds]
If a report id answers, it flips with device state -> candidate channel.
"""
import sys
import time
import hid

VID, PID = 0x35BB, 0xA217


def hexdump(raw):
    s = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in raw)
    return raw.hex(' ') + '  |' + s + '|'


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
    for d in hid.enumerate(VID, PID):
        label = (f'if{d["interface_number"]} page=0x{d["usage_page"]:04x} '
                 f'usage=0x{d["usage"]:04x}')
        try:
            h = hid.device()
            h.open_path(d['path'])
        except Exception as e:
            print(f'{label}: open FAILED {e}')
            continue
        print(f'--- {label} ---')
        try:
            # drain
            while h.read(64, timeout_ms=100):
                pass
            for rid in list(range(0x00, 0x11)):
                try:
                    data = h.get_feature_report(rid, 64)
                    if data:
                        print(f'  FEATURE id=0x{rid:02x} ({len(data):2d}) {hexdump(bytes(data))}')
                except Exception:
                    pass
            # listen a bit for async input
            deadline = time.time() + secs
            while time.time() < deadline:
                data = h.read(64, timeout_ms=int(secs * 1000))
                if data:
                    print(f'  INPUT  ({len(data):2d}) {hexdump(bytes(data))}')
        finally:
            h.close()


if __name__ == '__main__':
    main()
