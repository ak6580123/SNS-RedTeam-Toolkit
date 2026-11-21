using System.IO;
using System.Windows;

namespace ScripterSetup;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args;
        bool has(string a) => args.Any(x => x.Equals(a, StringComparison.OrdinalIgnoreCase));
        string? val(string a) { var i = Array.FindIndex(args, x => x.Equals(a, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }

        bool silent = has("--silent") || has("/S");
        bool uninstall = has("--uninstall") || Path.GetFileName(Environment.ProcessPath ?? "").Equals(Installer.UninstallerName, StringComparison.OrdinalIgnoreCase);
        var dir = val("--dir");
        var fromTemp = val("--from-temp");
        var removeWs = has("--remove-workspace");

        if (silent) { Shutdown(RunSilent(uninstall, dir, fromTemp, removeWs, args)); return; }

        var win = new MainWindow(uninstall, args, fromTemp, dir);
        win.Show();
        // temp-copy relaunch from Uninstall.exe proceeds without a second click
        if (uninstall && fromTemp != null)
            win.Dispatcher.InvokeAsync(() => win.MainBtn.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)));
    }

    static int RunSilent(bool uninstall, string? dir, string? fromTemp, bool removeWs, string[] args)
    {
        var log = Path.Combine(Path.GetTempPath(), "Scripter-Setup.log");
        void L(string s) { try { File.AppendAllText(log, $"{DateTime.Now:s} {s}\n"); } catch { } }
        try
        {
            if (uninstall)
            {
                var target = dir ?? Installer.FindExisting()?.Dir ?? Installer.DefaultDir;
                if (fromTemp == null && Installer.IsInside(Environment.ProcessPath, target))
                {
                    Installer.RelaunchFromTemp(target, args.Concat(new[] { "--dir", target }).ToArray());
                    return 0; // the temp copy finishes the job after this process exits
                }
                var ok = Installer.Uninstall(target, removeWs, (p, m) => L($"{p}% {m}"), false);
                if (fromTemp != null) Installer.FinishFromTemp(target, fromTemp);
                return ok ? 0 : 2;
            }
            var o = new InstallOptions
            {
                Dir = dir ?? Installer.FindExisting()?.Dir ?? Installer.DefaultDir,
                AddToPath = !args.Contains("--no-path"),
                StartMenu = !args.Contains("--no-startmenu"),
                Desktop = args.Contains("--desktop"),
            };
            Installer.Install(o, (p, m) => L($"{p}% {m}"));
            return 0;
        }
        catch (Exception ex) { L("ERROR: " + ex); return 1; }
    }
}
