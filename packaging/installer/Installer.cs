using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace ScripterSetup;

public sealed class InstallOptions
{
    public string Dir { get; set; } = Installer.DefaultDir;
    public bool AddToPath { get; set; } = true;
    public bool StartMenu { get; set; } = true;
    public bool Desktop { get; set; }
}

public sealed class Manifest
{
    public string Product { get; set; } = Installer.AppName;
    public string Version { get; set; } = "";
    public string InstallDir { get; set; } = "";
    public List<string> Files { get; set; } = new();
    public List<string> Dirs { get; set; } = new();
    public List<string> Shortcuts { get; set; } = new();
    public string? PathEntry { get; set; }
    public string RegistryKey { get; set; } = Installer.UninstallKey;
    public string WorkspaceDir { get; set; } = Installer.WorkspaceDir;
}

public static class Installer
{
    public const string AppName = "Scripter";
    public const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Scripter";
    public const string ManifestName = "install-manifest.json";
    public const string UninstallerName = "Uninstall.exe";

    public static string DefaultDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", AppName);
    public static string WorkspaceDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName);
    static string StartMenuDir => Environment.GetFolderPath(Environment.SpecialFolder.Programs);
    static string DesktopDir => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    public static string Version =>
        (Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0")
            .Split('+')[0];

    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    // ---------------------------------------------------------------- existing install

    public static (string Dir, string Version)? FindExisting()
    {
        using var k = Registry.CurrentUser.OpenSubKey(UninstallKey);
        var dir = k?.GetValue("InstallLocation") as string;
        if (string.IsNullOrWhiteSpace(dir) || !File.Exists(Path.Combine(dir, ManifestName))) return null;
        return (dir, k?.GetValue("DisplayVersion") as string ?? "?");
    }

    static Manifest? ReadManifest(string dir)
    {
        try { return JsonSerializer.Deserialize<Manifest>(File.ReadAllText(Path.Combine(dir, ManifestName))); }
        catch { return null; }
    }

    // ---------------------------------------------------------------- install

    public static void Install(InstallOptions o, Action<int, string> report)
    {
        var dir = Path.GetFullPath(o.Dir.Trim().Trim('"'));
        if (dir.Length <= 3) throw new InvalidOperationException("Choose a dedicated folder, not a drive root.");

        // Upgrade: remove what the previous install put down (never the user's workspace).
        var existing = FindExisting();
        if (existing is { } ex)
        {
            report(2, $"Removing previous version {ex.Version}...");
            Uninstall(ex.Dir, removeWorkspace: false, report: null, scheduleSelfDelete: false);
        }
        else if (File.Exists(Path.Combine(dir, ManifestName)))
        {
            Uninstall(dir, false, null, false);
        }

        var m = new Manifest { Version = Version, InstallDir = dir };
        try
        {
            Directory.CreateDirectory(dir);
            report(5, "Reading package...");
            var asm = Assembly.GetExecutingAssembly();
            using var res = asm.GetManifestResourceStream("payload.zip")
                ?? throw new InvalidOperationException("Installer is missing its payload.");
            using var zip = new ZipArchive(res, ZipArchiveMode.Read);
            var entries = zip.Entries.ToList();
            var root = dir.TrimEnd('\\') + "\\";
            var made = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < entries.Count; i++)
            {
                var e = entries[i];
                var rel = e.FullName.Replace('/', '\\');
                var dest = Path.GetFullPath(Path.Combine(dir, rel));
                if (!dest.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Payload contains an unsafe path: " + e.FullName);
                if (rel.EndsWith('\\') || e.Name.Length == 0) { Directory.CreateDirectory(dest); continue; }

                var parent = Path.GetDirectoryName(dest)!;
                TrackDirs(parent, dir, made);
                Directory.CreateDirectory(parent);
                e.ExtractToFile(dest, overwrite: true);
                m.Files.Add(rel);
                if (i % 25 == 0 || i == entries.Count - 1)
                    report(5 + (int)(80.0 * (i + 1) / entries.Count), $"Copying {Path.GetFileName(dest)}");
            }
            m.Dirs = made.ToList();

            report(87, "Writing uninstaller...");
            var self = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot locate installer exe.");
            File.Copy(self, Path.Combine(dir, UninstallerName), overwrite: true);
            m.Files.Add(UninstallerName);

            if (o.StartMenu) { report(90, "Creating Start Menu shortcut..."); m.Shortcuts.Add(MakeShortcut(StartMenuDir, dir)); }
            if (o.Desktop) { report(92, "Creating Desktop shortcut..."); m.Shortcuts.Add(MakeShortcut(DesktopDir, dir)); }
            if (o.AddToPath) { report(94, "Adding to PATH..."); if (AddToUserPath(dir)) m.PathEntry = dir; }

            report(96, "Registering with Windows...");
            RegisterUninstall(dir, m);
            m.Files.Add(ManifestName);
            File.WriteAllText(Path.Combine(dir, ManifestName), JsonSerializer.Serialize(m, Json));
            report(100, "Done");
        }
        catch
        {
            try { RollbackFrom(m); } catch { /* best effort */ }
            throw;
        }
    }

    static void TrackDirs(string dir, string installRoot, SortedSet<string> made)
    {
        var cur = dir;
        while (cur.Length > installRoot.Length && cur.StartsWith(installRoot, StringComparison.OrdinalIgnoreCase))
        {
            made.Add(Path.GetRelativePath(installRoot, cur));
            cur = Path.GetDirectoryName(cur) ?? break_();
        }
        static string break_() => "";
    }

    static string MakeShortcut(string folder, string dir)
    {
        Directory.CreateDirectory(folder);
        var lnk = Path.Combine(folder, AppName + ".lnk");
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell unavailable");
        dynamic shell = Activator.CreateInstance(shellType)!;
        try
        {
            dynamic s = shell.CreateShortcut(lnk);
            s.TargetPath = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            s.Arguments = $"-NoLogo -NoProfile -ExecutionPolicy Bypass -File \"{Path.Combine(dir, "launcher.ps1")}\"";
            s.WorkingDirectory = dir;
            s.IconLocation = Path.Combine(dir, "icon.ico");
            s.Description = "Scripter - authorized red-team automation";
            s.Save();
        }
        finally { Marshal.FinalReleaseComObject(shell); }
        return lnk;
    }

    static void RegisterUninstall(string dir, Manifest m)
    {
        long bytes = m.Files.Sum(f => { try { return new FileInfo(Path.Combine(dir, f)).Length; } catch { return 0; } });
        using var k = Registry.CurrentUser.CreateSubKey(UninstallKey);
        var un = Path.Combine(dir, UninstallerName);
        k.SetValue("DisplayName", AppName);
        k.SetValue("DisplayVersion", Version);
        k.SetValue("Publisher", AppName);
        k.SetValue("InstallLocation", dir);
        k.SetValue("DisplayIcon", Path.Combine(dir, "icon.ico"));
        k.SetValue("UninstallString", $"\"{un}\" --uninstall");
        k.SetValue("QuietUninstallString", $"\"{un}\" --uninstall --silent");
        k.SetValue("EstimatedSize", (int)(bytes / 1024), RegistryValueKind.DWord);
        k.SetValue("NoModify", 1, RegistryValueKind.DWord);
        k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        k.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
    }

    // ---------------------------------------------------------------- uninstall

    /// <summary>Removes exactly what the manifest lists. Returns true if the manifest was found.</summary>
    public static bool Uninstall(string dir, bool removeWorkspace, Action<int, string>? report, bool scheduleSelfDelete)
    {
        var m = ReadManifest(dir);
        if (m == null) { report?.Invoke(100, "No install manifest found."); return false; }
        RollbackFrom(m, removeWorkspace, report);
        return true;
    }

    static void RollbackFrom(Manifest m, bool removeWorkspace = false, Action<int, string>? report = null)
    {
        var dir = m.InstallDir;
        report?.Invoke(10, "Removing shortcuts...");
        foreach (var s in m.Shortcuts) TryDelete(s);

        report?.Invoke(25, "Removing PATH entry...");
        if (m.PathEntry != null) RemoveFromUserPath(m.PathEntry);

        // Interruption-safe order: the registry entry and manifest go LAST, so a killed
        // uninstall can simply be run again.
        report?.Invoke(40, "Deleting files...");
        var self = Environment.ProcessPath;
        foreach (var f in m.Files.Where(f => f != ManifestName).OrderByDescending(f => f.Length))
        {
            var p = Path.Combine(dir, f);
            if (self != null && string.Equals(Path.GetFullPath(p), Path.GetFullPath(self), StringComparison.OrdinalIgnoreCase)) continue;
            TryDelete(p, retries: 5);
        }
        report?.Invoke(80, "Removing folders...");
        foreach (var d in m.Dirs.OrderByDescending(d => d.Length)) TryRmdir(Path.Combine(dir, d));

        report?.Invoke(88, "Removing registry entries...");
        try { Registry.CurrentUser.DeleteSubKeyTree(m.RegistryKey, throwOnMissingSubKey: false); } catch { }
        TryDelete(Path.Combine(dir, ManifestName));
        TryRmdir(dir);

        if (removeWorkspace && Directory.Exists(m.WorkspaceDir))
        {
            report?.Invoke(92, "Removing workspace data...");
            try { Directory.Delete(m.WorkspaceDir, true); } catch { }
        }
        report?.Invoke(100, "Done");
    }

    static void TryDelete(string path, int retries = 1)
    {
        for (int i = 0; i < retries; i++)
        {
            try { if (File.Exists(path)) { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); } return; }
            catch { Thread.Sleep(200); }
        }
    }

    static void TryRmdir(string path)
    {
        try { if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any()) Directory.Delete(path); } catch { }
    }

    /// <summary>
    /// Uninstall.exe lives inside the install dir, so it can't delete itself. Copy to temp, run from there,
    /// and let that copy finish the job (it deletes the original, the dir, then itself).
    /// </summary>
    public static void RelaunchFromTemp(string dir, string[] args)
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"scripter-uninstall-{Guid.NewGuid():N}.exe");
        File.Copy(Environment.ProcessPath!, tmp, true);
        var psi = new ProcessStartInfo(tmp) { UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (!args.Contains("--uninstall")) psi.ArgumentList.Add("--uninstall");
        psi.ArgumentList.Add("--from-temp");
        psi.ArgumentList.Add(Environment.ProcessPath!);
        Process.Start(psi);
    }

    public static void FinishFromTemp(string dir, string originalExe)
    {
        for (int i = 0; i < 40; i++) // original exits right after relaunch; wait for its file lock to drop
        {
            try { if (File.Exists(originalExe)) File.Delete(originalExe); break; } catch { Thread.Sleep(250); }
        }
        TryRmdir(dir);
        // delete this temp copy after we exit
        Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping -n 3 127.0.0.1 >nul & del /f /q \"{Environment.ProcessPath}\"")
        { CreateNoWindow = true, UseShellExecute = false });
    }

    // ---------------------------------------------------------------- PATH (user scope)

    public static bool IsInside(string? file, string dir) =>
        file != null && Path.GetFullPath(file).StartsWith(Path.GetFullPath(dir).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    static string Norm(string s) => s.Trim().TrimEnd('\\').ToLowerInvariant();

    static bool AddToUserPath(string dir)
    {
        using var k = Registry.CurrentUser.OpenSubKey("Environment", writable: true)!;
        var cur = k.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames) as string ?? "";
        var parts = cur.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();
        if (parts.Any(p => Norm(p) == Norm(dir))) return false; // already there: we didn't add it, so we won't remove it
        parts.Add(dir);
        k.SetValue("Path", string.Join(';', parts), RegistryValueKind.ExpandString);
        BroadcastEnvChange();
        return true;
    }

    static void RemoveFromUserPath(string dir)
    {
        using var k = Registry.CurrentUser.OpenSubKey("Environment", writable: true);
        if (k == null) return;
        var cur = k.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames) as string ?? "";
        var parts = cur.Split(';', StringSplitOptions.RemoveEmptyEntries).Where(p => Norm(p) != Norm(dir)).ToList();
        k.SetValue("Path", string.Join(';', parts), RegistryValueKind.ExpandString);
        BroadcastEnvChange();
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);

    static void BroadcastEnvChange()
    {
        try { SendMessageTimeout((IntPtr)0xffff, 0x001A, UIntPtr.Zero, "Environment", 0x2, 2000, out _); } catch { }
    }
}
