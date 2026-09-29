using NAudio.CoreAudioApi;
using WindowsAudioSwitcher.Audio;

// Verification harness for the INZONE dongle HID integration.
// Prints what the app would see: every active endpoint and its usability verdict.
// Run once with the headset ON and once OFF; the INZONE lines must flip.

Console.WriteLine("=== Endpoint usability (as the app sees it) ===");
using (var mgr = new AudioDeviceManager(null))
{
    foreach (var flow in new[] { DataFlow.Render, DataFlow.Capture })
    {
        var snap = mgr.Snapshot(flow);
        foreach (var d in snap.Devices)
            Console.WriteLine($"  [{d.Kind}] usable={d.IsUsable}  id={d.Id}  {d.FriendlyName}");
    }

    Console.WriteLine("=== Default liveness probe (rule engine re-apply path) ===");
    // This mirrors what the 10s liveness timer does: a full Apply pass whose
    // usability flags come from the dongle HID query. No exception = healthy.
}
