# Detecting whether a USB-dongle headset is actually switched on

A reusable playbook for adding "real link state" detection for a new USB
wireless headset (dongle-based) to this app. Written after reverse-engineering
the Sony INZONE H9 II, then validated end-to-end on a second, entirely
different protocol family (HECATE GX03 Ultra — see case study below). The
method generalizes; the protocol details are device-specific.

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

Work through these in order. INZONE was cracked at step 1 + 5; HECATE needed
the vendor-app route (step 0) because HeadsetControl had nothing.

0. **Mine the vendor companion app's files first.** The install directory is a
   protocol treasure chest: `data/devices/*.json` often declares the VID/PID,
   capability flags (`need_check_connected`, `support_box_battery`) and even
   the control-channel path segments (HECATE: `"hid_path_feature":
   "mi_04&col03"`); `data/deviceresource/*/extrainfo.json` gives firmware
   versions (useful for validating captured bytes); native DLLs and strings
   reveal the chip vendor (JieLi/"JL" RCSP, Sony HCI, ...) which narrows the
   protocol family. `tools/hecate_pe_dump.py` is a template for dumping
   exports/imports/strings from those DLLs.
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
   `Leftover Capture Data`. Without USBPcap, Frida-hooking the app's HID API
   works: `tools/hecate_frida_hook.js` + `tools/hecate_frida_capture*.py`
   (CreateFileW/WriteFile/ReadFile/HidD_SetFeature/HidD_GetFeature). Two
   Frida traps: **the real I/O may live in a child process** (HECATE.exe
   spawns another HECATE.exe — hook *all* processes of the app, not the
   first), and on Frida 17 `Module.getExportByName` is gone (use
   `Module.getGlobalExportByName`), with HID.dll not yet mapped at spawn
   time (install those hooks lazily, on the first matching CreateFileW).
5. **Replay the query from Python** (`tools/inzone_status.py`,
   `tools/hecate_col03_query.py` are working templates) and verify it flips
   with the headset's power state. Only then port to C#.

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

## Case study: HECATE GX03 Ultra (JieLi chip, 2026-09)

Dongle: VID `0x35BB`, PID `0xA217`, USB composite. Audio on MI_00; HID on
MI_03 (vendor `0xFF02`, JieLi RCSP pushes starting `4a 4c` "JL" — separate
protocol, not needed) and MI_04 with five top-level collections (COL01
consumer, COL02–04 vendor `0xFF02`, COL05 telephony). **Control channel:
MI_04 & COL03** — confirmed by the vendor app's own
`data/devices/016_gx03.json` (`"hid_path_feature": "mi_04&col03"`) and
behaviorally (it is the only collection that answers). On Windows the
collection shows up in the HID device path as `&MI_04&COL03`, so path
matching works here.

Framing is trivial — report ID `0xD0` + VID as little-endian magic + command:

```
query (64-byte output report):  D0 35 BB 01 00 ... (zeros)
answer (input report):          D0 35 BB 09 00 <flags> <headsetBat> <caseBat> ...
                                                  [5]     [6]        [7]
```

- COL03 only accepts report-ID-0xD0 writes; anything else fails with -1.
- The dongle **answers even with the headset off** — the opposite of INZONE.
  Off = both battery bytes zero (`D0 35 BB 09 00 00 00 00 ...`), on = real
  percentages (`... 03 64 64 ...` = 100%/100%). Verified ON 3/3, OFF 4/4.
- **Trap:** don't use `[5]` (flags) for the connected decision — it takes
  varying non-zero values while on (03, 07, 0f...) and zero while off, but
  the battery bytes are the vendor app's authoritative source and stable.
- Async pushes share the `D0 35 BB` header: `01 01`/`01 00` = link
  up/down, `05 01 <st> <b1> <b2>` = battery, `07 02 <6b MAC>` = MAC,
  `09 ...` = status/version (same event the query elicits), `02 06` =
  ~30 s heartbeat with no state. Filter answers by `[3]==0x09 && [4]==0`.
- The vendor app itself only *listens* on COL03 (180 s of zero writes
  observed); our `D0 35 BB 01` query was found by probing, not by replay.

Implementation: `src/WindowsAudioSwitcher/Audio/HecateDongleStatus.cs`
(candidate preference: documented MI_04/COL03 path first, then every other
writable collection; answer — on *or* off — caches the control path).

## Integration pattern in this app

`src/WindowsAudioSwitcher/Audio/InzoneDongleStatus.cs` and
`HecateDongleStatus.cs` (C#, HidSharp) each expose
`GetStatus() → Status(DonglePresent, Connected, BatteryPercent)` with a 2 s
cache. Design decisions worth keeping for the next device:

- **`DonglePresent` must be distinguishable from `Connected`.** Presence =
  a known-PID device enumerates and a writable collection accepts our report;
  connection = it *answers*. Only cache the control-collection path after a
  real checksummed response, so a writable-but-silent impostor collection
  gets re-probed.
- Read budgets: 400 ms fast path, 300 ms per collection while identifying.
  Stale-report drain (few 50 ms reads) before each write; increment TID per
  query and match it in the response. (HECATE needs no TID — the frame has
  none; matching is by the fixed `0x09` event header.)
- **"Offline" semantics differ per dongle.** INZONE: silence within the read
  budget = off (the answer *is* the liveness signal). HECATE: the dongle
  answers on/off alike, so a timeout is abnormal — both are treated as
  `Connected=false`, which is the safe direction (never a false "usable").
- `AudioDeviceManager.IsUsable(device, isDefault)`: INZONE- and
  HECATE-with-dongle are **authoritative even for the current default** (no
  false negatives, unlike an exclusive-mode `IAudioClient` probe). Family
  match is by `FriendlyName` (contains "INZONE" / "HECATE" or "GX03").
  Everything else keeps `isDefault || probe` — never evict a default because
  a game grabbed it exclusively.
- **Known trap:** marking the default device unconditionally usable
  (`usable = isDefault || …`) makes the rule engine re-pick the dead default
  forever — eviction silently becomes a no-op. That's why INZONE (and now
  HECATE) are exempt from the short-circuit.
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
5. Vendor companion app running → still works (note if not). (HECATE: not
   re-tested with the app running after implementation; capture phase proved
   the collections open shared — see the tip below. INZONE: confirmed.)
6. Through the real app: log lines (`INZONE device …` / `HECATE device …
   => usable=…`) flip on both transitions and the default actually moves.
   (GX03 acceptance 2026-09-30: toggles 3/3 correct, dongle replug
   re-identifies the control channel with no crash, INZONE coexists.)

## Tool inventory

| Tool | Purpose |
|------|---------|
| `tools/hid_enum.py` | enumerate a VID's HID collections (usage pages, paths) |
| `tools/inzone_listen.py` | passive listener + periodic query, timestamps everything |
| `tools/inzone_probe.py` | one-shot battery/link query against every vendor collection |
| `tools/inzone_status.py` | standalone Python version of the final check (reference) |
| `tools/inzone_h5.hpp` | HeadsetControl's INZONE H5 driver — protocol reference |
| `tools/hecate_listen.py` | passive listener on all HECATE vendor collections |
| `tools/hecate_pe_dump.py` | exports/imports/strings dump for vendor app DLLs |
| `tools/hecate_frida_hook.js` + `hecate_frida_capture*.py` | Frida capture of the vendor app's HID I/O |
| `tools/hecate_col03_query.py` | standalone COL03 status query — final reference check |
| `diag/` | console harness that exercises the app's real `AudioDeviceManager` path |
