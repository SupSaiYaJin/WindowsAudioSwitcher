using System.Collections.Concurrent;
using NAudio.CoreAudioApi;
using NAudio.CoreAudioApi.Interfaces;
using WindowsAudioSwitcher.Logging;
using WindowsAudioSwitcher.Rules;

namespace WindowsAudioSwitcher.Audio;

/// <summary>
/// Enumerates audio endpoints, raises events on device changes, and switches default I/O.
/// Marshals all callbacks onto a single SynchronizationContext (typically the WPF dispatcher).
/// </summary>
public sealed class AudioDeviceManager : IDisposable, IMMNotificationClient
{
    private readonly MMDeviceEnumerator _enumerator = new();
    private readonly SynchronizationContext? _sync;

    // Per-device probe cache. USB wireless receivers (e.g. the INZONE H9 dongle) keep
    // their audio endpoint in DeviceState.Active even when the paired headset is powered
    // off, so the state flag alone can't tell us whether audio can actually be routed.
    // We resolve that per device family (see IsUsable); results are cached briefly so
    // enumeration doesn't pay the probe cost on every pass.
    private readonly ConcurrentDictionary<string, ProbeEntry> _probeCache = new();
    private static readonly TimeSpan ProbeCacheLifetime = TimeSpan.FromSeconds(8);
    private readonly InzoneDongleStatus _inzone = new();
    private bool _disposed;

    private readonly record struct ProbeEntry(bool Usable, DateTimeOffset CheckedAt);

    public event Action? DevicesChanged;

    public AudioDeviceManager(SynchronizationContext? sync)
    {
        _sync = sync;
        _enumerator.RegisterEndpointNotificationCallback(this);
    }

    public IReadOnlyList<AudioDevice> GetDevices(DataFlow flow)
    {
        var defaultId = TryGetDefaultId(flow);
        var list = new List<AudioDevice>();
        try
        {
            foreach (var d in _enumerator.EnumerateAudioEndPoints(flow, DeviceState.Active))
            {
                using (d)
                {
                    list.Add(BuildDevice(d, flow, defaultId));
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"EnumerateAudioEndPoints({flow}) failed", ex);
        }
        return list;
    }

    /// <summary>Enumerate active endpoints and read the default ID in one COM pass.</summary>
    public DeviceSnapshot Snapshot(DataFlow flow)
    {
        var defaultId = TryGetDefaultId(flow);
        var list = new List<AudioDevice>();
        try
        {
            foreach (var d in _enumerator.EnumerateAudioEndPoints(flow, DeviceState.Active))
            {
                using (d)
                {
                    list.Add(BuildDevice(d, flow, defaultId));
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"Snapshot({flow}) failed", ex);
        }
        return new DeviceSnapshot(list, defaultId);
    }

    /// <summary>
    /// Copy the fields we need out of the (short-lived) MMDevice and mark whether the
    /// endpoint is actually usable.
    /// </summary>
    private AudioDevice BuildDevice(MMDevice d, DataFlow flow, string? defaultId)
    {
        var isDefault = string.Equals(d.ID, defaultId, StringComparison.OrdinalIgnoreCase);
        var usable = IsUsable(d, isDefault);
        return new AudioDevice(d.ID, d.FriendlyName, flow, isDefault, usable);
    }

    /// <summary>
    /// True if the endpoint can actually play audio. The strategy depends on the device:
    /// <list type="bullet">
    ///   <item>INZONE wireless headsets: the USB dongle keeps its endpoint active and
    ///     even accepts an IAudioClient while the headset is off, so the generic probe
    ///     below cannot detect a powered-off headset. The dongle's vendor HID protocol
    ///     can (<see cref="InzoneDongleStatus"/>), and because that answer is
    ///     authoritative — no false negatives like an exclusive-mode grab — it applies
    ///     to the current default as well, which is what lets the liveness timer evict
    ///     (and later re-claim) a dongle-connected default. When no dongle is present
    ///     (e.g. INZONE over Bluetooth) we fall back to the generic probe.</item>
    ///   <item>Everything else: try to open a shared-mode IAudioClient stream. The
    ///     current default is exempt: if it is in exclusive use by another app the
    ///     probe would fail although the device is healthy, and we must not evict it
    ///     on that basis.</item>
    /// </list>
    /// Results are cached briefly so enumeration doesn't pay the probe cost on every pass.
    /// </summary>
    private bool IsUsable(MMDevice device, bool isDefault)
    {
        var id = device.ID;
        if (_probeCache.TryGetValue(id, out var entry) && DateTimeOffset.Now - entry.CheckedAt < ProbeCacheLifetime)
            return entry.Usable;

        bool usable;
        if (device.FriendlyName.Contains("INZONE", StringComparison.OrdinalIgnoreCase))
        {
            var status = _inzone.GetStatus();
            usable = status.DonglePresent
                ? status.Connected
                : isDefault || ProbeEndpoint(device); // BT fallback — keep default protection
            Logger.Info($"INZONE device '{device.FriendlyName}' dongle={status.DonglePresent} " +
                        $"connected={status.Connected} battery={status.BatteryPercent?.ToString() ?? "n/a"}% => usable={usable}");
        }
        else
        {
            usable = isDefault || ProbeEndpoint(device);
        }

        _probeCache[id] = new ProbeEntry(usable, DateTimeOffset.Now);
        return usable;
    }

    /// <summary>
    /// Actually opens the endpoint's IAudioClient and tries to initialize a shared-mode
    /// stream. For USB wireless receivers whose paired device is powered off, the driver
    /// rejects this (typically AUDCLNT_E_DEVICE_INVALIDATED) and we return false. The
    /// created stream is never started and is released when the MMDevice is disposed.
    /// </summary>
    private bool ProbeEndpoint(MMDevice device)
    {
        try
        {
            var client = device.AudioClient;
            if (client == null) return false;
            var format = client.MixFormat;
            if (format == null) return false;
            client.Initialize(AudioClientShareMode.Shared, AudioClientStreamFlags.None, 0L, 0L, format, Guid.Empty);
            return true;
        }
        catch (Exception ex)
        {
            Logger.Info($"Endpoint probe failed for '{device.FriendlyName}': {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    public string? TryGetDefaultId(DataFlow flow)
    {
        try
        {
            // GetDefaultAudioEndpoint returns an IDisposable MMDevice — dispose it
            // once we've pulled the ID so its COM handle isn't held until finalization.
            using var device = _enumerator.GetDefaultAudioEndpoint(flow, Role.Multimedia);
            return device.ID;
        }
        catch (Exception ex)
        {
            // E_NOTFOUND is normal for a flow with no devices (e.g. no mic) — log at debug only.
            Logger.Info($"GetDefaultAudioEndpoint({flow}) returned no device ({ex.GetType().Name}: {ex.Message})");
            return null;
        }
    }

    public void SetDefault(string deviceId)
    {
        Logger.Info($"SetDefault({deviceId}) — calling IPolicyConfigVista");
        try
        {
            PolicyConfig.SetDefaultDevice(deviceId);
            Logger.Info($"SetDefault({deviceId}) OK");
        }
        catch (Exception ex)
        {
            Logger.Error($"SetDefault({deviceId}) failed", ex);
            throw;
        }
    }

    private void Raise([System.Runtime.CompilerServices.CallerMemberName] string caller = "")
    {
        Logger.Info($"IMMNotificationClient.{caller}");
        // Device topology or state changed — cached probe results may be stale
        // (e.g. a wireless headset just powered on or off). Drop them so the
        // next enumeration re-probes every endpoint.
        _probeCache.Clear();
        try
        {
            if (_sync != null) _sync.Post(_ =>
            {
                try { DevicesChanged?.Invoke(); }
                catch (Exception ex) { Logger.Error($"DevicesChanged handler threw ({caller})", ex); }
            }, null);
            else DevicesChanged?.Invoke();
        }
        catch (Exception ex)
        {
            Logger.Error($"Raise({caller}) failed", ex);
        }
    }

    void IMMNotificationClient.OnDeviceStateChanged(string deviceId, DeviceState newState) => Raise();
    void IMMNotificationClient.OnDeviceAdded(string pwstrDeviceId) => Raise();
    void IMMNotificationClient.OnDeviceRemoved(string deviceId) => Raise();
    void IMMNotificationClient.OnDefaultDeviceChanged(DataFlow flow, Role role, string defaultDeviceId) => Raise();

    // Wireless USB receivers often report headset power state as a property change
    // rather than a full device-state transition, so react to those too.
    void IMMNotificationClient.OnPropertyValueChanged(string pwstrDeviceId, PropertyKey key) => Raise();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _enumerator.UnregisterEndpointNotificationCallback(this); } catch { }
        _enumerator.Dispose();
    }
}
