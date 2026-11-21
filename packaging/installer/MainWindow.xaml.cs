using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;

namespace ScripterSetup;

public partial class MainWindow : Window
{
    enum Stage { Options, Working, Done, Uninstall }
    Stage _stage;
    readonly bool _uninstallMode;
    readonly string[] _args;
    readonly string? _fromTemp;
    string _launchDir = "";
    bool _busy;

    public MainWindow(bool uninstallMode, string[] args, string? fromTemp, string? dirOverride)
    {
        InitializeComponent();
        _uninstallMode = uninstallMode; _args = args; _fromTemp = fromTemp;
        VersionText.Text = "Version " + Installer.Version;

        var existing = Installer.FindExisting();
        DirBox.Text = dirOverride ?? existing?.Dir ?? Installer.DefaultDir;

        if (uninstallMode)
        {
            var dir = dirOverride ?? existing?.Dir ?? Installer.DefaultDir;
            _launchDir = dir;
            TitleBar.Text = Heading.Text = "Scripter Uninstall";
            ShowStage(Stage.Uninstall);
            UninstallText.Text = $"This will remove Scripter from:\n{dir}\n\nShortcuts, the PATH entry and the Add/Remove Programs entry are removed too.";
        }
        else
        {
            if (existing is { } ex)
            {
                ExistingNote.Text = $"Version {ex.Version} is already installed at {ex.Dir}. Setup will upgrade it in place; your workspace and config are kept.";
                ExistingNote.Visibility = Visibility.Visible;
            }
            ShowStage(Stage.Options);
        }
    }

    void ShowStage(Stage s)
    {
        _stage = s;
        PageOptions.Visibility = s == Stage.Options ? Visibility.Visible : Visibility.Collapsed;
        PageProgress.Visibility = s == Stage.Working ? Visibility.Visible : Visibility.Collapsed;
        PageDone.Visibility = s == Stage.Done ? Visibility.Visible : Visibility.Collapsed;
        PageUninstall.Visibility = s == Stage.Uninstall ? Visibility.Visible : Visibility.Collapsed;
        CancelBtn.Visibility = s is Stage.Options or Stage.Uninstall ? Visibility.Visible : Visibility.Collapsed;
        MainBtn.IsEnabled = s != Stage.Working;
        MainBtn.Content = s switch { Stage.Options => "Install", Stage.Uninstall => "Uninstall", Stage.Done => "Finish", _ => "Working..." };
    }

    void Drag(object s, MouseButtonEventArgs e) { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); }
    void CloseClick(object s, RoutedEventArgs e) { if (!_busy) Close(); }

    void BrowseClick(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Choose install folder", InitialDirectory = Directory.Exists(DirBox.Text) ? DirBox.Text : null };
        if (dlg.ShowDialog(this) == true)
        {
            // keep installs in a dedicated subfolder when the user picks a generic parent
            var p = dlg.FolderName;
            DirBox.Text = Path.GetFileName(p.TrimEnd('\\')).Equals("Scripter", StringComparison.OrdinalIgnoreCase) ? p : Path.Combine(p, "Scripter");
        }
    }

    async void MainClick(object s, RoutedEventArgs e)
    {
        switch (_stage)
        {
            case Stage.Options: await RunInstall(); break;
            case Stage.Uninstall: await RunUninstall(); break;
            case Stage.Done:
                if (!_uninstallMode && LaunchCheck.IsChecked == true) Launch();
                Close();
                break;
        }
    }

    async Task RunInstall()
    {
        var opts = new InstallOptions
        {
            Dir = DirBox.Text, AddToPath = PathCheck.IsChecked == true,
            StartMenu = MenuCheck.IsChecked == true, Desktop = DesktopCheck.IsChecked == true,
        };
        _launchDir = Path.GetFullPath(opts.Dir.Trim().Trim('"'));
        ShowStage(Stage.Working); _busy = true;
        try
        {
            await Task.Run(() => Installer.Install(opts, (pct, msg) => Dispatcher.Invoke(() =>
            {
                Bar.Value = pct; Percent.Text = pct + "%"; StatusText.Text = msg;
            })));
            DoneTitle.Text = "Installation complete";
            DoneText.Text = $"Scripter {Installer.Version} was installed to:\n{_launchDir}" +
                (opts.AddToPath ? "\n\nOpen a new terminal to use the 'scripter' command." : "");
            ShowStage(Stage.Done);
        }
        catch (Exception ex)
        {
            DoneTitle.Text = "Installation failed";
            DoneText.Text = ex.Message + "\n\nAny partial changes were rolled back.";
            LaunchCheck.Visibility = Visibility.Collapsed;
            ShowStage(Stage.Done);
        }
        finally { _busy = false; }
    }

    async Task RunUninstall()
    {
        // The uninstaller lives inside the folder it deletes; continue from a temp copy.
        if (_fromTemp == null && Installer.IsInside(Environment.ProcessPath, _launchDir))
        {
            var a = _args.ToList();
            if (WorkspaceCheck.IsChecked == true) a.Add("--remove-workspace");
            if (!a.Contains("--dir")) { a.Add("--dir"); a.Add(_launchDir); }
            a.Add("--auto");
            Installer.RelaunchFromTemp(_launchDir, a.ToArray());
            Close();
            return;
        }
        ShowStage(Stage.Working); _busy = true;
        try
        {
            bool remove = WorkspaceCheck.IsChecked == true || _args.Contains("--remove-workspace");
            bool found = await Task.Run(() => Installer.Uninstall(_launchDir, remove, (pct, msg) => Dispatcher.Invoke(() =>
            {
                Bar.Value = pct; Percent.Text = pct + "%"; StatusText.Text = msg;
            }), false));
            DoneTitle.Text = found ? "Scripter was removed" : "Nothing to remove";
            DoneText.Text = found ? "All installed files, shortcuts, PATH and registry entries were removed." : "No install manifest was found at that location.";
            LaunchCheck.Visibility = Visibility.Collapsed;
            ShowStage(Stage.Done);
            if (_fromTemp != null) await Task.Run(() => Installer.FinishFromTemp(_launchDir, _fromTemp));
        }
        catch (Exception ex)
        {
            DoneTitle.Text = "Uninstall failed"; DoneText.Text = ex.Message; LaunchCheck.Visibility = Visibility.Collapsed;
            ShowStage(Stage.Done);
        }
        finally { _busy = false; }
    }

    void Launch()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                $"-NoLogo -NoProfile -ExecutionPolicy Bypass -File \"{Path.Combine(_launchDir, "launcher.ps1")}\"")
            { WorkingDirectory = _launchDir, UseShellExecute = true });
        }
        catch { }
    }
}
