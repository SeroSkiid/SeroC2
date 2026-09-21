using System.IO;
using System.Text.Json;

namespace SeroStub;

internal static class FileSearchFeature
{
    internal static string Search(string rootPath, string pattern, bool recursive, int maxResults)
    {
        var results = new List<FmSearchEntryStub>();
        string error = "";
        try
        {
            rootPath = Environment.ExpandEnvironmentVariables(rootPath.Trim());
            if (string.IsNullOrEmpty(rootPath) || !Directory.Exists(rootPath))
            {
                error = "Directory not found.";
            }
            else
            {
                SearchDir(rootPath, pattern, recursive, results, maxResults);
            }
        }
        catch (Exception ex) { error = ex.Message; }
        return JsonSerializer.Serialize(
            new FmSearchResultStub { Results = results, Error = error },
            SeroJson.Default.FmSearchResultStub);
    }

    private static void SearchDir(string dir, string pattern, bool recursive, List<FmSearchEntryStub> results, int max)
    {
        if (results.Count >= max) return;
        try
        {
            foreach (var f in Directory.EnumerateFiles(dir, pattern, SearchOption.TopDirectoryOnly))
            {
                if (results.Count >= max) return;
                try
                {
                    var fi = new FileInfo(f);
                    results.Add(new FmSearchEntryStub { Name = fi.Name, FullPath = f, Size = fi.Length, IsDir = false });
                }
                catch { }
            }
            if (!recursive) return;
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                if (results.Count >= max) return;
                try { SearchDir(sub, pattern, true, results, max); }
                catch { }
            }
        }
        catch { }
    }
}

internal class FmSearchEntryStub  { public string Name { get; set; } = ""; public string FullPath { get; set; } = ""; public long Size { get; set; } public bool IsDir { get; set; } }
internal class FmSearchResultStub { public List<FmSearchEntryStub> Results { get; set; } = []; public string Error { get; set; } = ""; }
internal class FmSearchDataStub   { public string Path { get; set; } = ""; public string Pattern { get; set; } = "*"; public bool Recursive { get; set; } = true; public int MaxResults { get; set; } = 500; }
