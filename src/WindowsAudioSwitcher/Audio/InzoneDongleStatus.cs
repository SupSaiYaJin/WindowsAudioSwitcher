using System.IO;
using HidSharp;
using WindowsAudioSwitcher.Logging;

namespace WindowsAudioSwitcher.Audio;

/// <summary>Link state of an INZONE headset as seen by its USB dongle.</summary>
/// <param name="DonglePresent">A known INZONE dongle (H9 II / H5) is plugged in.</param>
/// <param name="Connected">The headset is powered on and linked to the dongle.</param>
/// <param name="BatteryPercent">Battery 0..100 while connected; null otherwise.</param>
public sealed record InzoneStatus(bool DonglePresent, bool Connected, int? BatteryPercent)
{
    public static readonly InzoneStatus Absent = new(false, false, null);
}

/// <summary>
/// Queries the Sony INZONE USB 2.4GHz receiver over its vendor HID collection to
/// learn whether the paired headset is actually powered on (plus battery level).
///
/// Why this exists: the dongle keeps its audio endpoints in DeviceState.Active even
/// when the headset is off, and on this device the endpoints even accept an
/// IAudioClient — so WASAPI probing cannot distinguish "dongle plugged in" from
/// "headset connected". The vendor protocol can.
///
/// Protocol (reverse-engineered from HeadsetControl's Sony INZONE H5 driver and
/// verified live against an INZONE H9 II, which shares it):
///   - Dongle PIDs: 0x0FA8 (H9 II), 0x0EBF (H5). VID 0x054C. The control channel
///     is the dongle's Sony-vendor top-level HID collection (usage page 0xFF04),
///     which is the only collection that accepts our 64-byte output reports.
///   - Reports carry a Sony vendor HCI frame: report ID 0x02, magic key 0x96 0xC3,
///     opcode 0xFC00, trailing checksum. A battery GET (event 0x04, type 0x01) is
///     answered with event type 0x10 (RET) and payload [charger, percent] — but
///     ONLY while the headset is on. Offline, the dongle is silent.
///   - The control channel is therefore identified behaviorally: write the query,
///     see who answers (checksummed, matching transaction id).
/// </summary>
internal sealed class InzoneDongleStatus
{
    private const ushort SonyVendorId = 0x054C;
    private static readonly ushort[] DongleProductIds = { 0x0FA8, 0x0EBF }; // H9 II, H5

    private const int ReportSize = 64;
    private const byte ReportId = 0x02;
    private const byte KeyLo = 0x96;
    private const byte KeyHi = 0xC3;
    private const byte AddrPcToRx = 0x41; // (Dst=RX << 4) | Src=PC
    private const byte EidBattery = 0x04;
    private const byte EtypeGet = 0x01;

    // Read budgets per query. A connected headset answers in <100 ms, so these only
    // bound the wait when the headset is off. During control-channel identification
    // several collections are tried in sequence, so keep that budget shorter.
    private const int ReadBudgetMs = 400;
    private const int IdentifyReadBudgetMs = 300;

    private static readonly TimeSpan StatusCacheLifetime = TimeSpan.FromSeconds(2);

    private readonly object _lock = new();
    private InzoneStatus _cached = InzoneStatus.Absent;
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    // Device path of the collection that last answered a query. Only cached after
    // a real (checksummed) response so a silent impostor collection is re-probed.
    private string? _controlPath;
    private ushort _tid = 0x0041;

    /// <summary>Cached link status (TTL a couple of seconds — dongle queries are not free).</summary>
    public InzoneStatus GetStatus()
    {
        lock (_lock)
        {
            if (DateTimeOffset.Now - _cachedAt < StatusCacheLifetime)
                return _cached;
            try
            {
                _cached = Query();
            }
            catch (Exception ex)
            {
                Logger.Info($"InzoneDongleStatus: query failed ({ex.GetType().Name}: {ex.Message})");
                _cached = InzoneStatus.Absent;
            }
            _cachedAt = DateTimeOffset.Now;
            if (_cached.DonglePresent)
                Logger.Info($"InzoneDongleStatus: present={_cached.DonglePresent} connected={_cached.Connected} battery={_cached.BatteryPercent?.ToString() ?? "n/a"}%");
            return _cached;
        }
    }

    private InzoneStatus Query()
    {
        var devices = DeviceList.Local.GetHidDevices(SonyVendorId, null)
            .Where(d => Array.IndexOf(DongleProductIds, (ushort)d.ProductID) >= 0)
            .ToList();
        if (devices.Count == 0)
        {
            _controlPath = null;
            return InzoneStatus.Absent;
        }

        // Fast path: the collection that answered last time, still present.
        if (_controlPath != null)
        {
            var known = devices.FirstOrDefault(d =>
                string.Equals(d.DevicePath, _controlPath, StringComparison.OrdinalIgnoreCase));
            if (known != null)
            {
                var status = RunQuery(known, ReadBudgetMs);
                if (status.DonglePresent)
                    return status; // answered (on or off) — authoritative
                // Open/write failed (e.g. transient USB hiccup) — fall through to
                // the identification scan instead of reporting the dongle absent.
            }
            _controlPath = null;
        }

        // Identification pass: try every collection that can accept a 64-byte
        // output report; the first one to answer a checksummed battery GET is the
        // control channel. A writable-but-silent collection means the dongle is
        // present with the headset off (don't cache its path — it is unproven).
        InzoneStatus presentButSilent = new(true, false, null);
        foreach (var d in devices.Where(d => d.GetMaxOutputReportLength() >= ReportSize))
        {
            var status = RunQuery(d, IdentifyReadBudgetMs);
            if (status.Connected)
            {
                _controlPath = d.DevicePath;
                return status;
            }
        }
        return presentButSilent;
    }

    private InzoneStatus RunQuery(HidDevice device, int readBudgetMs)
    {
        try
        {
            if (!device.TryOpen(out HidStream stream))
                return InzoneStatus.Absent;

            using (stream)
            {
                stream.ReadTimeout = 50;
                stream.WriteTimeout = 200;

                // Drain stale reports so an old battery answer can't be mistaken
                // for the fresh one (our transaction id is reused across queries).
                var scratch = new byte[ReportSize];
                for (int i = 0; i < 4; i++)
                {
                    int stale;
                    try { stale = stream.Read(scratch, 0, ReportSize); }
                    catch (TimeoutException) { break; }
                    catch (IOException) { break; }
                    if (stale <= 0) break;
                }

                ushort tid = NextTid();
                stream.Write(BuildBatteryGet(tid));

                long deadline = Environment.TickCount64 + readBudgetMs;
                var buf = new byte[ReportSize];
                while (Environment.TickCount64 < deadline)
                {
                    int n;
                    try { n = stream.Read(buf, 0, ReportSize); }
                    catch (TimeoutException) { continue; }
                    if (n <= 0) continue;

                    var evt = ParseEvent(buf);
                    if (evt.HasValue && evt.Value.Eid == EidBattery && evt.Value.Tid == tid)
                    {
                        var payload = evt.Value.Payload;
                        if (payload.Length >= 2 && payload[1] <= 100)
                            return new InzoneStatus(true, true, payload[1]);
                        // 0xFF placeholder = headset offline per H5 semantics.
                        return new InzoneStatus(true, false, null);
                    }
                }
                return new InzoneStatus(true, false, null);
            }
        }
        catch (Exception ex)
        {
            // Typical for non-vendor collections (Consumer/Telephony) that reject
            // our writes — not the control channel.
            Logger.Info($"InzoneDongleStatus: {device.DevicePath} probe failed ({ex.GetType().Name}: {ex.Message})");
            return InzoneStatus.Absent;
        }
    }

    private ushort NextTid()
    {
        // TID 0/1 belong to dongle-initiated notifications; skip them.
        _tid = _tid >= 0xFFFF ? (ushort)2 : (ushort)(_tid + 1);
        return _tid;
    }

    /// <summary>Build a battery GET as a 64-byte output report (Sony vendor HCI).</summary>
    private static byte[] BuildBatteryGet(ushort tid)
    {
        var buf = new byte[ReportSize];
        buf[0] = ReportId;
        buf[1] = 12;            // hid_length: HCI bytes that follow, no payload
        buf[2] = 0x01;          // HCI command
        buf[3] = 0x00;          // opcode 0xFC00 LE
        buf[4] = 0xFC;
        buf[5] = 8;             // param_length
        buf[6] = KeyLo;
        buf[7] = KeyHi;
        buf[8] = AddrPcToRx;
        buf[9] = EidBattery;
        buf[10] = EtypeGet;
        buf[11] = (byte)(tid & 0xFF);
        buf[12] = (byte)(tid >> 8);
        buf[13] = Checksum(buf, 6, 13);
        return buf;
    }

    private static byte Checksum(byte[] buf, int from, int toExclusive)
    {
        int sum = 0;
        for (int i = from; i < toExclusive; i++) sum += buf[i];
        return (byte)sum;
    }

    private readonly struct SonyEvent
    {
        public byte Eid { get; init; }
        public ushort Tid { get; init; }
        public byte[] Payload { get; init; }
    }

    /// <summary>
    /// Validate and parse an incoming report. Returns null unless it is a
    /// well-formed Sony vendor HCI event addressed to the host (checksum verified).
    /// </summary>
    private static SonyEvent? ParseEvent(byte[] buf)
    {
        if (buf.Length < ReportSize || buf[0] != ReportId)
            return null;
        int len = buf[1];
        if (len < 12 || len > ReportSize - 2)
            return null;
        if (buf[2] != 0x04 || buf[3] != 0xFF || buf[5] != 0x00)
            return null;
        if (buf[6] != KeyLo || buf[7] != KeyHi)
            return null;
        if ((buf[8] >> 4) != 0x1) // destination must be PC
            return null;
        if (Checksum(buf, 5, len + 1) != buf[len + 1])
            return null;

        var payload = new byte[Math.Max(0, len - 12)];
        Array.Copy(buf, 13, payload, 0, payload.Length);
        return new SonyEvent
        {
            Eid = buf[9],
            Tid = (ushort)(buf[11] | (buf[12] << 8)),
            Payload = payload,
        };
    }
}
