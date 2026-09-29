using NAudio.CoreAudioApi;

namespace WindowsAudioSwitcher.Audio;

public sealed record AudioDevice(string Id, string FriendlyName, DataFlow Flow, bool IsDefault, bool IsUsable = true)
{
    public string Kind => Flow == DataFlow.Render ? "Output" : "Input";
}
