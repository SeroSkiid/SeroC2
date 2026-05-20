using DiscordRPC;
using System;
using System.Windows.Threading;

namespace SeroServer.Net;

public class SeroDiscordRPC : IDisposable
{
    private DiscordRpcClient? _client;
    private DispatcherTimer? _timer;
    private readonly string _appId;
    private Func<int>? _getClientCount;
    private DateTime _startTime;

    public SeroDiscordRPC(string applicationId = "1488910856074035433")
    {
        _appId = applicationId;
    }

    public void Start(Func<int> getClientCount)
    {
        _getClientCount = getClientCount;
        _startTime = DateTime.UtcNow;

        _client = new DiscordRpcClient(_appId);
        _client.Initialize();

        UpdatePresence();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _timer.Tick += (_, _) => UpdatePresence();
        _timer.Start();
    }

    private void UpdatePresence()
    {
        if (_client == null || _client.IsDisposed) return;

        var count = _getClientCount?.Invoke() ?? 0;
        try
        {
            _client.SetPresence(new RichPresence
            {
                Details = "Sero",
                State = $"{count} friend{(count != 1 ? "s" : "")} online",
                Timestamps = new Timestamps { Start = _startTime }
            });
        }
        catch { }
    }

    public void Stop()
    {
        _timer?.Stop();
        _timer = null;

        if (_client != null && !_client.IsDisposed)
        {
            try
            {
                _client.ClearPresence();
                _client.Dispose();
            }
            catch { }
        }
        _client = null;
    }

    public void Dispose() => Stop();
}
