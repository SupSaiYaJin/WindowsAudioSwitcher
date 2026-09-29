# Detecting whether a USB-dongle headset is actually switched on

A reusable playbook for adding "real link state" detection for a new USB
wireless headset (dongle-based) to this app. Written after reverse-engineering
the Sony INZONE H9 II; the method generalizes, the protocol details are
INZONE-specific.

## The problem

USB 2.4 GHz receivers keep their audio endpoints registered and
`DeviceState.Active` 24/7 — the dongle is powered as long as it sits in the USB
port. On some devices (INZONE H9 II confirmed) the endpoints even accept a
shared-mode `IAudioClient` while the headset is off, so **every WASAPI-level
probe reports "ready" for a dead headset**. Windows fires no device event when
the headset itself powers on/off. The only reliable source of truth is the
dongle's **vendor-defined HID interface**, which the vendor's own companion app
(INZONE Hub etc.) uses to show connection status and battery.

## Recon checklist for a new headset

Work through these in order. The INZONE H9 II was cracked at step 1 + 5.

1. **Check [HeadsetControl](https://github.com/Sapd/HeadsetControl) first.**
   `lib/devices/*.hpp` in that repo contains ready-made protocol code for many
   gaming headsets. Same vendor / same product line often means the same
   protocol with a different USB PID (that's exactly how H9 II reused H5's
   protocol). If found, skip to step 5.
2. **Enumerate the vendor HID collections.** Use `tools/hid_enum.py`
   (adjust VID/PID). One line per top-level collection; you want
   `usage_page >= 0xFF00` (vendor-defined). Record PID, usage_page/usage, path.
   Collections for keyboard/mouse-like usages cannot be opened from user mode.
3. **Passive listening.** `tools/inzone_listen.py` style: open each vendor
   collection, log every input report with timestamps while toggling the
   headset on/off. Some dongles push status notifications only on transitions.
4. **Capture the vendor app's traffic** (only if 2–3 yield nothing):
   USBPcap + Wireshark, filter `usb.idVendor == 0x...`, then
   `usb.setup.bRequest == 0x09` (SET_REPORT) / `0x01` (GET_REPORT) and
   interrupt transfers. The query command and the state bytes appear in
   `Leftover Capture Data`.
5. **Replay the query from Python** (`tools/inzone_status.py` is a working
   template) and verify it flips with the headset's power state. Only then port
   to C#.

Tips that saved time here:

- The vendor app (INZONE Hub) can keep running — Windows HID collections open
  shared, multiple readers coexist. Kill it only if opens actually fail.
- Identify the control channel **behaviorally**, not by usage page: send a
  known query, and the collection that answers a checksum-valid response *is*
  the control channel. Descriptor parsing libraries (HidSharp) don't expose
  usage pages cleanly anyway.
- Match the transaction id (TID) of your query in the response, and drain
  stale reports first — dongle-initiated notifications get queued in the OS
  input buffer and will otherwise be misread.

## Case study: Sony INZONE protocol (H9 II / H5)

Dongle: VID `0x054C`, PID `0x0FA8` (H9 II) / `0x0EBF` (H5). Control channel is
the dongle's Sony-vendor top-level collection, usage page `0xFF04` — the only
one that accepts our 64-byte output reports (a second vendor page, `0xFF13`,
rejects writes).

Everything is wrapped in a Sony vendor HCI frame inside Report ID `0x02`:

```
[0]  report id 0x02
[1]  len            HCI bytes that follow (12 + payload)
[2]  0x01 CMD / 0x04 EVT
[3-4] opcode 0x00 0xFC (LE)          (events: [3]=0xFF, [5]=0x00)
[5]  param length (8 + payload)
[6-7] magic key 0x96 0xC3            — constant across INZONE products
[8]  address  (Dst<<4)|Src; 1=PC, 2=TX(dongle), 4=RX(headset); PC→RX = 0x41
[9]  event id (EID)
[10] event type (0x01 GET, 0x10 RET, 0xA0 NTFY_ACTIVE)
[11-12] tid LE                       — echo in response; 0/1 = dongle-initiated
[13..]  payload
[n]  checksum = sum(bytes 5..len) & 0xFF, stored at [len+1]
```

Useful EIDs (H9 II — superset of H5's):

| EID   | Meaning | Notes |
|-------|---------|-------|
| 0x04  | Battery | GET → RET payload `[charger, percent]`, 0x00–0x64; 0xFF = offline |
| 0x01  | 2.4 GHz link status | notify-only (GET unanswered); push `payload[0]` 1=connected on power-on |
| 0x41  | audio/stream info pushes | observed at connect |
| 0x61  | audio state pushes | sample-rate-ish pairs |

**Offline = silence.** A powered-off headset answers nothing; the dongle sends
nothing on its own either. The battery GET therefore doubles as a liveness
probe: answer within budget = on, budget expiry = off (also treat `0xFF` as
off, per H5 semantics). A connected headset answers in <100 ms.

## Integration pattern in this app

`src/WindowsAudioSwitcher/Audio/InzoneDongleStatus.cs` (C#, HidSharp) exposes
`GetStatus() → InzoneStatus(DonglePresent, Connected, BatteryPercent)` with a
2 s cache. Design decisions worth keeping for the next device:

- **`DonglePresent` must be distinguishable from `Connected`.** Presence =
  a known-PID device enumerates and a writable collection accepts our report;
  connection = it *answers*. Only cache the control-collection path after a
  real checksummed response, so a writable-but-silent impostor collection
  gets re-probed.
- Read budgets: 400 ms fast path, 300 ms per collection while identifying.
  Stale-report drain (few 50 ms reads) before each write; increment TID per
  query and match it in the response.
- `AudioDeviceManager.IsUsable(device, isDefault)`: INZONE-with-dongle is
  **authoritative even for the current default** (no false negatives, unlike
  an exclusive-mode `IAudioClient` probe). Everything else keeps
  `isDefault || probe` — never evict a default because a game grabbed it
  exclusively.
- **Known trap:** marking the default device unconditionally usable
  (`usable = isDefault || …`) makes the rule engine re-pick the dead default
  forever — eviction silently becomes a no-op. That's why INZONE is exempt
  from the short-circuit.
- `App`'s 10 s liveness timer simply re-runs `ApplyRules` every tick. With the
  point above fixed, one mechanism covers both directions of a silent power
  toggle: headset off → dongle default becomes unusable → fall back; headset
  on → it becomes the best rule target again → re-claim. `ApplyRules` is a
  no-op when the target is already the default.

## Acceptance test protocol

For any new device implementation, before shipping:

1. Headset on → status reports connected (with battery if available).
2. Headset off, wait 5–10 s → reports disconnected.
3. Toggle on/off three times — every transition correct.
4. Dongle unplugged → "not found", no crash.
5. Vendor companion app running → still works (note if not).
6. Through the real app: log lines (`INZONE device … => usable=…`) flip on
   both transitions and the default actually moves.

## Tool inventory

| Tool | Purpose |
|------|---------|
| `tools/hid_enum.py` | enumerate a VID's HID collections (usage pages, paths) |
| `tools/inzone_listen.py` | passive listener + periodic query, timestamps everything |
| `tools/inzone_probe.py` | one-shot battery/link query against every vendor collection |
| `tools/inzone_status.py` | standalone Python version of the final check (reference) |
| `tools/inzone_h5.hpp` | HeadsetControl's INZONE H5 driver — protocol reference |
| `diag/` | console harness that exercises the app's real `AudioDeviceManager` path |
