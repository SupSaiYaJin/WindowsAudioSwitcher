"""Passive listener for the HECATE GX03 Ultra USB 2.4G dongle (VID 0x35BB PID 0xA217).

Opens every vendor-defined collection (usage_page 0xFF02, interfaces 3 and 4)
and logs every incoming input report with a timestamp. Run while toggling the
headset on/off to spot dongle-initiated status pushes.

Usage: python hecate_listen.py [seconds] [--poll]
  --poll additionally hammers nothing; passive only for now.
"""
import sys
import time
import threading
import hid

VID, PID = 0x35BB, 0xA217
VENDOR_PAGE = 0xFF02


def ts():
    return time.strftime('%H:%M:%S') + f'.{int(time.time() * 1000) % 1000:03d}'


def reader(path, label, stop_evt):
    try:
        h = hid.device()
        h.open_path(path)
    except Exception as e:
        print(f'[{ts()}] {label} open failed: {e}', flush=True)
        return
    print(f'[{ts()}] {label} opened for read', flush=True)
    while not stop_evt.is_set():
        try:
            data = h.read(64, timeout_ms=300)
        except Exception as e:
            print(f'[{ts()}] {label} read error: {e}', flush=True)
            break
        if data:
            raw = bytes(data)
            print(f'[{ts()}] {label} IN ({len(raw):2d}) {raw.hex(" ")}', flush=True)
    h.close()


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    paths = []
    for d in hid.enumerate(VID, PID):
        if d['usage_page'] == VENDOR_PAGE:
            paths.append((d['interface_number'], d['path']))
    # dedupe per interface+col by path string
    seen, uniq = set(), []
    for ifc, p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append((ifc, p))
    if not uniq:
        print('no vendor collections found')
        return
    stop_evt = threading.Event()
    threads = []
    for i, (ifc, p) in enumerate(uniq):
        t = threading.Thread(target=reader, args=(p, f'if{ifc}#{i}', stop_evt), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)
    print(f'listening {dur}s on {len(uniq)} vendor collections ...', flush=True)
    time.sleep(dur)
    stop_evt.set()
    time.sleep(0.5)
    print('done', flush=True)


if __name__ == '__main__':
    main()
