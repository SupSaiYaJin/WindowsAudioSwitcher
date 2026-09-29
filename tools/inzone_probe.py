"""Probe H9 II dongle vendor collections with the H5-style Sony HCI protocol.

Frame format (from HeadsetControl sony_inzone_h5.hpp):
  write: [0]=report_id 0x02, [1]=hid_length=12+payload,
         [2]=0x01 (HCI CMD), [3..4]=0x00 0xFC, [5]=8+payload,
         [6..7]=0x96 0xC3, [8]=address, [9]=event_id, [10]=event_type,
         [11..12]=tid LE, [13..]=payload, [13+pl]=checksum(sum(buf[6..12+pl])&0xFF)
  parse: buf[0]=0x02, buf[2]=0x04 (HCI EVT), buf[3]=0xFF, buf[5]=0x00,
         buf[6..7]=0x96 0xC3, addr=buf[8] (dst nibble 1=PC),
         eid=buf[9], etype=buf[10], tid=buf[11]|buf[12]<<8, payload=buf[13..hid_length]
"""
import sys
import time
import hid

VID = 0x054C
PID = 0x0FA8
REPORT_ID = 0x02
KEY_LO, KEY_HI = 0x96, 0xC3
ADDR_PC_TO_RX = 0x41
EID_CONNECT_STATUS = 0x01
EID_BATTERY = 0x04
ETYPE_GET = 0x01

TARGETS = [0xFF13, 0xFF04]  # usage pages to try


def find_paths():
    out = {}
    for d in hid.enumerate(VID, PID):
        if d['usage_page'] in TARGETS:
            out.setdefault(d['usage_page'], []).append(d['path'])
    return out


def build_cmd(event_id, etype=ETYPE_GET, tid=0x0042, payload=b''):
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


def try_parse(buf):
    if not buf or buf[0] != REPORT_ID:
        return None
    hl = buf[1]
    if hl < 12 or hl > 62:
        return None
    if buf[2] != 0x04 or buf[3] != 0xFF or buf[5] != 0x00:
        return None
    if buf[6] != KEY_LO or buf[7] != KEY_HI:
        return None
    s = sum(buf[5:hl + 1]) & 0xFF
    if s != buf[hl + 1]:
        return f'CHECKSUM-FAIL raw={bytes(buf[:20]).hex(" ")}'
    return {
        'addr': buf[8],
        'eid': buf[9],
        'etype': buf[10],
        'tid': buf[11] | (buf[12] << 8),
        'payload': bytes(buf[13:hl + 1]),
    }


def probe(path, label):
    print(f'\n--- {label} ---')
    try:
        h = hid.device()
        h.open_path(path)
    except Exception as e:
        print(f'  open FAILED: {e}')
        return
    try:
        print('  opened:', h.get_manufacturer_string(), '|', h.get_product_string())
        # flush stale input
        while h.read(64, timeout_ms=100):
            pass
        for eid, name in [(EID_BATTERY, 'BATTERY'), (EID_CONNECT_STATUS, 'CONNECT_STATUS')]:
            cmd = build_cmd(eid, tid=0x0042)
            n = h.write(cmd)
            print(f'  write {name}: {n} bytes')
            got = False
            deadline = time.time() + 2.0
            while time.time() < deadline:
                data = h.read(64, timeout_ms=300)
                if not data:
                    continue
                raw = bytes(data)
                p = try_parse(raw)
                if p:
                    print(f'  EVENT eid=0x{p["eid"]:02x} etype=0x{p["etype"]:02x} '
                          f'addr=0x{p["addr"]:02x} tid={p["tid"]} payload={p["payload"].hex(" ")}')
                else:
                    print(f'  RAW    {raw[:24].hex(" ")}')
                got = True
                break
            if not got:
                print(f'  {name}: no response')
            time.sleep(0.2)
    finally:
        h.close()


def main():
    paths = find_paths()
    if not paths:
        print('receiver not found')
        sys.exit(1)
    for page, plist in paths.items():
        for i, p in enumerate(plist):
            probe(p, f'usage_page=0x{page:04x} #{i}')


if __name__ == '__main__':
    main()
