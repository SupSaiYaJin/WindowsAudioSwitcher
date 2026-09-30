using System.IO;
using HidSharp;
using WindowsAudioSwitcher.Logging;

namespace WindowsAudioSwitcher.Audio;

/// <summary>Link state of a HECATE (Edifier) headset as seen by its USB 2.4GHz dongle.</summary>
/// <param name="DonglePresent">A known HECATE dongle is plugged in.</param>
/// <param name="Connected">The headset is powered on and linked to the dongle.</param>
/// <param name="BatteryPercent">Headset battery 0..100 while connected; null otherwise.</param>
public sealed record HecateStatus(bool DonglePresent, bool Connected, int? BatteryPercent)
{
    public static readonly HecateStatus Absent = new(false, false, null);
}

/// <summary>
/// Queries the HECATE GX03 Ultra USB dongle over its vendor HID collection to learn
/// whether the paired headset is actually powered on (plus battery level).
///
/// Why this exists: same problem as the INZONE dongle (<see cref="InzoneDongleStatus"/>) —
/// the dongle keeps its audio endpoints in DeviceState.Active even when the headset
/// is off, so WASAPI probing cannot distinguish "dongle plugged in" from "headset
/// connected". The vendor protocol can.
///
/// Protocol (reverse-engineered and verified live; see docs/usb-dongle-link-detection.md):
///   - Dongle: VID 0x35BB, PID 0xA217 (USB composite device). The control channel is
///     the 3rd top-level collection of the MI_04 HID interface (vendor usage page
///     0xFF02); on Windows it shows up in the device path as "&amp;MI_04&amp;COL03" —
///     the vendor app's config matches the same path segments ("mi_04&amp;col03").
///   - Query: 64-byte output report [0xD0, 0x35, 0xBB, 0x01, 0x00...] — report ID
///     0xD0, VID as little-endian magic, command 0x01 = "get status". COL03 only
///     accepts report ID 0xD0 writes.
///   - Answer: input report [0xD0, 0x35, 0xBB, 0x09, 0x00, flags, headsetBattery,
///     caseBattery, ...]. Unlike INZONE, the dongle answers even with the headset
///     powered off — then both battery bytes are zero. Connected iff either battery
///     byte is non-zero (verified live: ON 3/3, OFF 4/4).
///   - Unrelated input reports (async connect/battery/MAC pushes, ~30s heartbeats)
///     share the D0/35/BB header and are skipped by the 0x09 event filter.
/// </summary>
internal sealed class HecateDongleStatus
{
    private const ushort VendorId = 0x35BB;
    private static readonly ushort[] DongleProductIds = { 0xA217 }; // GX03 Ultra dongle

    private const int ReportSize = 64;
    private const byte ReportId = 0xD0;
    private const byte MagicLo = 0x35; // VID 0x35BB little-endian
    private const byte MagicHi = 0xBB;
    private const byte CmdGetStatus = 0x01;
    private const byte EvtStatus = 0x09;

    // Read budgets per query. The dongle answers quickly whether the headset is on
    // or off, so these only bound a pathological silence. Identification tries
    // several collections in sequence, so keep that budget shorter.
    private const int ReadBudgetMs = 400;
    private const int IdentifyReadBudgetMs = 300;

    private static readonly TimeSpan StatusCacheLifetime = TimeSpan.FromSeconds(2);

    private readonly object _lock = new();
    private HecateStatus _cached = HecateStatus.Absent;
    private DateTimeOffset _cachedAt = DateTimeOffset.MinValue;

    // Device path of the collection that last answered a status query. Only cached
    // after a header-validated response so a silent collection is re-probed.
    private string? _controlPath;

    /// <summary>Cached link status (TTL a couple of seconds — dongle queries are not free).</summary>
    public HecateStatus GetStatus()
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
                Logger.Info($"HecateDongleStatus: query failed ({ex.GetType().Name}: {ex.Message})");
                _cached = HecateStatus.Absent;
            }
            _cachedAt = DateTimeOffset.Now;
            if (_cached.DonglePresent)
                Logger.Info($"HecateDongleStatus: present={_cached.DonglePresent} connected={_cached.Connected} battery={_cached.BatteryPercent?.ToString() ?? "n/a"}%");
            return _cached;
        }
    }

    private HecateStatus Query()
    {
        var devices = DeviceList.Local.GetHidDevices(VendorId, null)
            .Where(d => Array.IndexOf(DongleProductIds, (ushort)d.ProductID) >= 0)
            .ToList();
        if (devices.Count == 0)
        {
            _controlPath = null;
            return HecateStatus.Absent;
        }

        // Fast path: the collection that answered last time, still present.
        if (_controlPath != null)
        {
            var known = devices.FirstOrDefault(d =>
                string.Equals(d.DevicePath, _controlPath, StringComparison.OrdinalIgnoreCase));
            if (known != null)
            {
                var status = RunQuery(known, ReadBudgetMs);
                if (status != null)
                    return status; // authoritative (connected or off)
                // Open/write failed (e.g. transient USB hiccup) — fall through to
                // the identification scan instead of trusting a stale verdict.
            }
            _controlPath = null;
        }

        // Identification pass. The dongle answers a status query whether or not the
        // headset is powered on, so any collection whose answer validates IS the
        // control channel — connected and offline answers are equally identifying.
        // Prefer the vendor app's documented MI_04/COL03 path, then try the rest.
        foreach (var d in OrderCandidates(devices))
        {
            var status = RunQuery(d, IdentifyReadBudgetMs);
            if (status != null)
            {
                _controlPath = d.DevicePath;
                return status;
            }
        }
        // Dongle present but nothing answered — treat as offline (never a false "usable").
        return new HecateStatus(true, false, null);
    }

    private static IEnumerable<HidDevice> OrderCandidates(IEnumerable<HidDevice> devices)
    {
        return devices
            .Where(d => d.GetMaxOutputReportLength() >= ReportSize)
            .OrderByDescending(d => IsDocumentedControlPath(d.DevicePath) ? 1 : 0);
    }

    private static bool IsDocumentedControlPath(string path)
    {
        // Vendor app config: hid_path_feature = "mi_04&col03".
        return path.Contains("&COL03", StringComparison.OrdinalIgnoreCase)
            && path.Contains("&MI_04", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Send one status query and wait for the answer.
    /// Returns the parsed status, or null if the collection stayed silent / rejected us.
    /// </summary>
    private HecateStatus? RunQuery(HidDevice device, int readBudgetMs)
    {
        try
        {
            if (!device.TryOpen(out HidStream stream))
                return null;

            using (stream)
            {
                stream.ReadTimeout = 50;
                stream.WriteTimeout = 200;

                // Drain stale reports (async pushes/heartbeats pile up between queries)
                // so an old status event can't be mistaken for the fresh answer.
                var scratch = new byte[ReportSize];
                for (int i = 0; i < 4; i++)
                {
                    int stale;
                    try { stale = stream.Read(scratch, 0, ReportSize); }
                    catch (TimeoutException) { break; }
                    catch (IOException) { break; }
                    if (stale <= 0) break;
                }

                stream.Write(BuildStatusQuery());

                long deadline = Environment.TickCount64 + readBudgetMs;
                var buf = new byte[ReportSize];
                while (Environment.TickCount64 < deadline)
                {
                    int n;
                    try { n = stream.Read(buf, 0, ReportSize); }
                    catch (TimeoutException) { continue; }
                    if (n <= 0) continue;
                    if (!IsStatusEvent(buf)) continue;

                    int headset = buf[6];
                    int chargeCase = buf[7];
                    bool connected = headset != 0 || chargeCase != 0;
                    int? battery = connected && headset <= 100 ? headset : null;
                    return new HecateStatus(true, connected, battery);
                }
                return null;
            }
        }
        catch (Exception ex)
        {
            // Typical for non-vendor collections (Consumer/Telephony) that reject
            // our writes — not the control channel.
            Logger.Info($"HecateDongleStatus: {device.DevicePath} probe failed ({ex.GetType().Name}: {ex.Message})");
            return null;
        }
    }

    /// <summary>Build the "get status" query as a 64-byte output report.</summary>
    private static byte[] BuildStatusQuery()
    {
        var buf = new byte[ReportSize];
        buf[0] = ReportId;
        buf[1] = MagicLo;
        buf[2] = MagicHi;
        buf[3] = CmdGetStatus;
        return buf;
    }

    private static bool IsStatusEvent(byte[] buf)
    {
        return buf.Length >= 8
            && buf[0] == ReportId
            && buf[1] == MagicLo
            && buf[2] == MagicHi
            && buf[3] == EvtStatus
            && buf[4] == 0x00;
    }
}
