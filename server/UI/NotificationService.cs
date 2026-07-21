using System.IO;
using System.Windows.Media;
using System.Drawing;
using System.Windows.Forms;

namespace SeroServer.UI;

public static class NotificationService
{
    private static NotifyIcon? _trayIcon;
    private static MediaPlayer? _player;
    private static bool _soundsEnabled;
    private static bool _visualEnabled;
    private static long _lastConnectSoundTicks;
    private static System.Drawing.Bitmap? _seroBmp;   // kept alive so GetHicon() handle stays valid
    private static System.Drawing.Icon?   _seroIcon;  // notification icon from serofondtransparent.png

    private static string S(string file) =>
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Sounds", file);

    private static readonly string SndIntro = S("Intro.wav");

    // startup_shutdown
    private static readonly string SndStartup    = S("01_startup_chime.mp3");
    private static readonly string SndShutdown   = S("04_shutdown_gentle_descent.mp3");

    // network
    private static readonly string SndConnected    = S("34_device_connected.mp3");
    private static readonly string SndDisconnected = S("35_device_disconnected.mp3");

    // system
    private static readonly string SndSuccess = S("11_success_bright.mp3");
    private static readonly string SndError   = S("13_error_buzz.mp3");

    // retro
    private static readonly string SndCoinCollect = S("41_8bit_coin_collect.mp3");
    private static readonly string SndMailChime   = S("45_mail_chime.mp3");
    private static readonly string SndPowerUp     = S("40_8bit_power_up.mp3");

    // actions
    private static readonly string SndDownload   = S("26_download_complete.mp3");
    private static readonly string SndUpload     = S("27_upload_complete.mp3");
    private static readonly string SndFileDel    = S("23_file_deletion.mp3");
    private static readonly string SndScanDone   = S("20_scan_complete.mp3");

    public static void Initialize(bool soundsEnabled, bool visualEnabled)
    {
        _soundsEnabled = soundsEnabled;
        _visualEnabled = visualEnabled;

        // sero.ico is a WPF embedded resource — load it via pack URI, not filesystem path
        Icon icon;
        try
        {
            var sri = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/sero.ico"));
            icon = sri != null ? new Icon(sri.Stream) : SystemIcons.Application;
        }
        catch { icon = SystemIcons.Application; }

        _trayIcon = new NotifyIcon { Icon = icon, Visible = true, Text = "SeroC2 Server" };

        // Build notification icon from serofondtransparent.png (kept alive as static bitmap)
        try
        {
            var sri2 = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/serofondtransparent.png"));
            if (sri2 != null)
            {
                using var raw = new System.Drawing.Bitmap(sri2.Stream);
                _seroBmp  = new System.Drawing.Bitmap(raw, 256, 256);
                _seroIcon = System.Drawing.Icon.FromHandle(_seroBmp.GetHicon());
            }
        }
        catch { }

        PlayIntro();
    }

    public static void SetEnabled(bool soundsEnabled, bool visualEnabled)
    {
        _soundsEnabled = soundsEnabled;
        _visualEnabled = visualEnabled;
    }

    private static bool IsSndEnabled(string key)
    {
        return UiPrefs.GetInt("SndEnabled_" + key, 1) == 1;
    }

    public static void PlayPreviewFile(string fileName)
    {
        PlaySound(S(fileName));
    }

    // ── Always plays (server lifecycle) ──────────────────────────────────────
    public static void PlayIntro()
    {
        if (IsSndEnabled("Intro")) PlaySound(SndIntro);
    }
    public static void PlayStartup()
    {
        if (IsSndEnabled("Startup")) PlaySound(SndStartup);
    }
    public static void PlayShutdown()
    {
        if (IsSndEnabled("Shutdown")) PlaySound(SndShutdown);
    }

    // ── Gated by notification checkbox ───────────────────────────────────────
    public static void NotifyConnected(string clientId, bool isNewHwid = false)
    {
        if (_visualEnabled)
            ShowBalloon(isNewHwid ? Lang.Get("NOTIF_NEW_CLIENT") : Lang.Get("NOTIF_CLIENT_CONNECTED"), clientId, ToolTipIcon.Info);

        if (!_soundsEnabled) return;

        // Debounce: only play a sound if at least 400ms passed since the last connect sound.
        // Prevents a blast of simultaneous sounds when many clients reconnect at startup.
        long now  = DateTime.UtcNow.Ticks;
        long last = Interlocked.Read(ref _lastConnectSoundTicks);
        if (now - last > TimeSpan.TicksPerMillisecond * 400)
        {
            Interlocked.Exchange(ref _lastConnectSoundTicks, now);
            if (isNewHwid)
            {
                if (IsSndEnabled("NewClient")) PlaySound(SndPowerUp);
            }
            else
            {
                if (IsSndEnabled("Connected")) PlaySound(SndConnected);
            }
        }
    }

    public static void NotifyDisconnected(string clientId)
    {
        if (_soundsEnabled && IsSndEnabled("Disconnected")) PlaySound(SndDisconnected);
        if (_visualEnabled) ShowBalloon(Lang.Get("NOTIF_CLIENT_DISCONNECTED"), clientId, ToolTipIcon.Warning);
    }

    public static void NotifyBuildSuccess() { if (_soundsEnabled && IsSndEnabled("BuildSuccess")) PlaySound(SndSuccess); }
    public static void NotifyBuildError()   { if (_soundsEnabled && IsSndEnabled("BuildError")) PlaySound(SndError); }

    public static void NotifyClipperTriggered() { if (_soundsEnabled && IsSndEnabled("Clipper")) PlaySound(SndCoinCollect); }
    public static void NotifyKeylogReceived()   { if (_soundsEnabled && IsSndEnabled("Keylogger")) PlaySound(SndMailChime); }
    public static void NotifyAutoTaskDone()     { if (_soundsEnabled && IsSndEnabled("AutoTask")) PlaySound(SndScanDone); }

    public static void NotifyWindowAlert(string keyword, string window)
    {
        if (_visualEnabled) ShowBalloon(Lang.Get("NOTIF_WIN_ALERT"), $"{keyword} — {window}", ToolTipIcon.Warning);
        if (_soundsEnabled && IsSndEnabled("WinAlert")) PlaySound(SndMailChime);
    }

    public static void NotifyDownloadComplete() { if (_soundsEnabled && IsSndEnabled("Download")) PlaySound(SndDownload); }
    public static void NotifyUploadComplete()   { if (_soundsEnabled && IsSndEnabled("Upload")) PlaySound(SndUpload); }
    public static void NotifyFileDeleted()      { if (_soundsEnabled && IsSndEnabled("FileDelete")) PlaySound(SndFileDel); }

    public static void Shutdown()
    {
        _trayIcon?.Dispose();
        _trayIcon = null;
    }

    private static void PlaySound(string path)
    {
        if (!File.Exists(path)) return;
        System.Windows.Application.Current.Dispatcher.BeginInvoke(() =>
        {
            _player?.Stop();
            _player ??= new MediaPlayer();
            _player.Open(new Uri(path, UriKind.Absolute));
            _player.Play();
        });
    }

    private static void ShowBalloon(string title, string text, ToolTipIcon _)
        => NotificationPopup.Enqueue(title, text);
}
