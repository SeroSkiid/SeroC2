using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;

namespace SeroStub;

/// <summary>
/// Loads plugin DLLs at runtime and routes packets to the correct plugin.
/// Only works in SingleFile mode — NativeAOT does not support Assembly.Load.
/// </summary>
internal class PluginHost : IDisposable
{
    private readonly ConcurrentDictionary<int, ISeroPlugin> _handlers = new();
    private readonly List<ISeroPlugin> _plugins = new();
    private readonly Func<int, string, Task> _sendBack;

    public PluginHost(Func<int, string, Task> sendBack)
    {
        _sendBack = sendBack;
    }

    /// <summary>
    /// Load a plugin DLL from raw bytes. Scans for ISeroPlugin implementations,
    /// instantiates them, and registers their packet type handlers.
    /// Returns the list of plugin names loaded.
    /// </summary>
    public List<string> LoadPlugin(byte[] dllBytes)
    {
        var loaded = new List<string>();

        try
        {
            var ctx = new AssemblyLoadContext(null, isCollectible: false);
            var asm = ctx.LoadFromStream(new MemoryStream(dllBytes));

            foreach (var type in asm.GetExportedTypes())
            {
                if (!typeof(ISeroPlugin).IsAssignableFrom(type) || type.IsAbstract || type.IsInterface)
                    continue;

                var plugin = (ISeroPlugin)Activator.CreateInstance(type)!;
                _plugins.Add(plugin);

                foreach (var pktType in plugin.HandledTypes)
                {
                    _handlers[pktType] = plugin;
                }

                loaded.Add(plugin.Name);
                StubLog.Info($"[Plugin] Loaded: {plugin.Name} (handles {plugin.HandledTypes.Length} packet types)");
            }
        }
        catch (Exception ex)
        {
            StubLog.Error($"[Plugin] Load failed: {ex.Message}");
        }

        return loaded;
    }

    /// <summary>Returns true if a plugin is registered for this packet type.</summary>
    public bool CanHandle(int packetType) => _handlers.ContainsKey(packetType);

    /// <summary>Route a packet to the appropriate plugin handler.</summary>
    public async Task HandleAsync(int packetType, string data, CancellationToken ct)
    {
        if (_handlers.TryGetValue(packetType, out var plugin))
        {
            try
            {
                await plugin.HandleAsync(packetType, data, _sendBack, ct);
            }
            catch (Exception ex)
            {
                StubLog.Error($"[Plugin] {plugin.Name} error: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        foreach (var p in _plugins)
        {
            try { p.Dispose(); } catch { }
        }
        _plugins.Clear();
        _handlers.Clear();
    }
}
