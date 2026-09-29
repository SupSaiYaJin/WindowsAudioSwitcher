"""Listen on H9 II dongle vendor collections.

- Opens usage_page 0xFF04 (writable) and 0xFF13 (read-only) simultaneously.
- Logs every incoming report with timestamp.
- Every 3 s, sends BATTERY (0x04) and CONNECT_STATUS (0x01) GET on 0xFF04.

Run for a fixed duration (arg, seconds, default 90).
"""
import sys
import time
import threading
import hid

VID, PID = 0x054C, 0x0FA8
REPORT_ID = 0x02
KEY_LO, KEY_HI = 0x96, 0xC3
ADDR_PC_TO_RX = 0x41


def build_cmd(event_id, etype=0x01, tid=0x0042, payload=b''):
    plen = len(payload)
    buf = bytearray(64)
    buf[0] = REPORT_ID
    buf[1] = 12 + plen
    buf[2] = 0x01
    buf[3] = 0x00
    buf[4] = 0xFC
    buf[5] = 8 + plen
    buf[6] = KEY_LO
    buf[7] = KEY_HI
    buf[8] = ADDR_PC_TO_RX
    buf[9] = event_id
    buf[10] = etype
    buf[11] = tid & 0xFF
    buf[12] = (tid >> 8) & 0xFF
    for i, b in enumerate(payload):
        buf[13 + i] = b
    buf[13 + plen] = sum(buf[6:13 + plen + 1]) & 0xFF
    return bytes(buf)


def ts():
    return time.strftime('%H:%M:%S')


def reader(path, label, stop_evt):
    try:
        h = hid.device()
        h.open_path(path)
    except Exception as e:
        print(f'[{label}] open failed: {e}', flush=True)
        return
    print(f'[{ts()}] {label} opened for read', flush=True)
    while not stop_evt.is_set():
        try:
            data = h.read(64, timeout_ms=300)
        except Exception as e:
            print(f'[{ts()}] {label} read error: {e}', flush=True)
            break
        if data:
            print(f'[{ts()}] {label} IN  {bytes(data[:24]).hex(" ")}', flush=True)
    h.close()


def poller(path, stop_evt):
    try:
        h = hid.device()
        h.open_path(path)
    except Exception as e:
        print(f'[poll] open failed: {e}', flush=True)
        return
    print(f'[{ts()}] poll opened', flush=True)
    while not stop_evt.is_set():
        for eid, name in [(0x04, 'BAT'), (0x01, 'CON')]:
            n = h.write(build_cmd(eid, tid=0x0042))
            if n < 0:
                print(f'[{ts()}] poll {name} write={n}', flush=True)
            deadline = time.time() + 0.6
            while time.time() < deadline:
                data = h.read(64, timeout_ms=200)
                if data:
                    print(f'[{ts()}] poll {name} RSP {bytes(data[:24]).hex(" ")}', flush=True)
                    break
        stop_evt.wait(3.0)
    h.close()


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 90
    paths = {}
    for d in hid.enumerate(VID, PID):
        if d['usage_page'] in (0xFF04, 0xFF13) and d['usage_page'] not in paths:
            paths[d['usage_page']] = d['path']
    if not paths:
        print('receiver not found', flush=True)
        return
    stop_evt = threading.Event()
    threads = []
    for page, p in paths.items():
        t = threading.Thread(target=reader, args=(p, f'0x{page:04x}', stop_evt), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)
    if 0xFF04 in paths:
        pt = threading.Thread(target=poller, args=(paths[0xFF04], stop_evt), daemon=True)
        pt.start()
        threads.append(pt)
    print(f'listening for {dur}s ...', flush=True)
    time.sleep(dur)
    stop_evt.set()
    time.sleep(0.5)
    print('done', flush=True)


if __name__ == '__main__':
    main()
