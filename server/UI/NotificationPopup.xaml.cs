using System.Windows;
using System.Windows.Media.Animation;

namespace SeroServer.UI;

public partial class NotificationPopup : Window
{
    private const double DisplayMs = 2500;
    private const double FadeInMs  = 200;
    private const double FadeOutMs = 280;
    private const double SlideInPx = 20;
    private const int    MaxQueued = 6;

    private static readonly Queue<(string Title, string Body)> _queue = new();
    private static bool _isShowing;

    // Called from NotificationService — safe to call from any thread
    public static void Enqueue(string title, string body)
    {
        System.Windows.Application.Current.Dispatcher.BeginInvoke(() =>
        {
            if (_queue.Count < MaxQueued)
                _queue.Enqueue((title, body));
            if (!_isShowing)
                ShowNext();
        });
    }

    private static void ShowNext()
    {
        if (_queue.Count == 0) { _isShowing = false; return; }
        _isShowing = true;
        var (title, body) = _queue.Dequeue();
        new NotificationPopup(title, body).Show();
    }

    public NotificationPopup(string title, string body)
    {
        InitializeComponent();
        TxtTitle.Text = title;
        TxtBody.Text  = body;
        Loaded += OnLoaded;
    }

    private void OnLoaded(object s, RoutedEventArgs e)
    {
        var area    = SystemParameters.WorkArea;
        double finalTop = area.Bottom - Height - 16;
        Left = area.Right - Width - 16;
        Top  = finalTop + SlideInPx;

        Opacity = 0;
        var easeOut = new QuadraticEase { EasingMode = EasingMode.EaseOut };
        BeginAnimation(OpacityProperty,
            new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(FadeInMs)) { EasingFunction = easeOut });

        var sbSlide   = new Storyboard();
        var slideAnim = new DoubleAnimation(finalTop + SlideInPx, finalTop, TimeSpan.FromMilliseconds(FadeInMs + 40))
            { EasingFunction = easeOut };
        Storyboard.SetTarget(slideAnim, this);
        Storyboard.SetTargetProperty(slideAnim, new PropertyPath(TopProperty));
        sbSlide.Children.Add(slideAnim);
        sbSlide.Begin();

        ProgressBar.BeginAnimation(WidthProperty,
            new DoubleAnimation(264, 0, TimeSpan.FromMilliseconds(DisplayMs)));

        var timer = new System.Windows.Threading.DispatcherTimer
            { Interval = TimeSpan.FromMilliseconds(DisplayMs) };
        timer.Tick += (_, _) => { timer.Stop(); FadeOut(); };
        timer.Start();
    }

    private void FadeOut()
    {
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(FadeOutMs))
            { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn } };
        fade.Completed += (_, _) => { Close(); ShowNext(); };
        BeginAnimation(OpacityProperty, fade);
    }
}
