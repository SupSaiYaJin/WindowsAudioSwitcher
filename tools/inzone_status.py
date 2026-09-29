"""Detect whether the Sony INZONE H9 II headset is powered on/connected via its
USB 2.4GHz receiver (dongle), plus battery level.

Protocol (reverse-engineered, matches Sony vendor HCI used by INZONE H5):
  - Dongle: VID 0x054C, PID 0x0FA8, HID collection usage_page 0xFF04.
  - 64-byte reports, Report ID 0x02, wrapping a Sony vendor HCI frame:
      write: [0]=0x02 [1]=len [2]=0x01(CMD) [3..4]=0x00FC [5]=paramlen
             [6..7]=key 0x96C3 [8]=addr [9]=event_id [10]=event_type
             [11..12]=tid LE [13..]=payload [n]=checksum
      event: [2]=0x04(EVT) [3]=0xFF [6..7]=key, addr dst nibble 1=PC,
             checksum = sum(buf[5..hid_length]) & 0xFF at buf[hid_length+1]
  - BATTERY_INFO (EID 0x04) GET -> RET payload [charger, percent];
    percent 0xFF means headset offline. While the headset is OFF the dongle
    does not answer at all, which is the offline signal.
"""
import sys
import time
import hid

VID = 0x054C
PID = 0x0FA8
USAGE_PAGE = 0xFF04
REPORT_ID = 0x02
KEY_LO, KEY_HI = 0x96, 0xC3
ADDR_PC_TO_RX = 0x41
EID_BATTERY = 0x04
ETYPE_GET = 0x01
QUERY_TIMEOUT_S = 2.5


def find_path():
    for d in hid.enumerate(VID, PID):
        if d['usage_page'] == USAGE_PAGE:
            return d['path']
    return None


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


def parse_event(buf):
    if len(buf) < 15 or buf[0] != REPORT_ID:
        return None
    hl = buf[1]
    if hl < 12 or hl > 62:
        return None
    if buf[2] != 0x04 or buf[3] != 0xFF or buf[5] != 0x00:
        return None
    if buf[6] != KEY_LO or buf[7] != KEY_HI:
        return None
    if sum(buf[5:hl + 1]) & 0xFF != buf[hl + 1]:
        return None
    return {
        'addr': buf[8],
        'eid': buf[9],
        'etype': buf[10],
        'tid': buf[11] | (buf[12] << 8),
        'payload': bytes(buf[13:hl + 1]),
    }


def query_battery(h, tid=0x0042):
    """Return (charger, percent) if headset is connected, else None."""
    if h.write(build_cmd(EID_BATTERY, ETYPE_GET, tid)) < 0:
        raise OSError('HID write failed')
    deadline = time.time() + QUERY_TIMEOUT_S
    while time.time() < deadline:
        data = h.read(64, timeout_ms=250)
        if not data:
            continue
        p = parse_event(bytes(data))
        if p and p['eid'] == EID_BATTERY and p['tid'] == tid:
            if len(p['payload']) < 2:
                return None
            charger, percent = p['payload'][0], p['payload'][1]
            if percent == 0xFF or percent > 100:
                return None
            return charger, percent
    return None


def main():
    path = find_path()
    if path is None:
        print('receiver not found')
        return 1
    try:
        h = hid.device()
        h.open_path(path)
    except OSError as e:
        print(f'failed to open receiver: {e}')
        print('hint: fully exit INZONE Hub and retry')
        return 1
    try:
        while h.read(64, timeout_ms=100):
            pass
        result = query_battery(h)
        if result is None:
            print('connected: False')
            return 0
        charger, percent = result
        status = 'charging' if charger else 'discharging'
        print(f'connected: True')
        print(f'battery: {percent}% ({status})')
        return 0
    finally:
        h.close()


if __name__ == '__main__':
    sys.exit(main())
