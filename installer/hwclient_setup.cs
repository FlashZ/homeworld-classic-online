using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class HWClientSetup
{
    private const string DefaultServerHost = "hw1.lanflat.net";
    private const int DefaultGatewayPort = 15101;
    private const string DefaultDisplayCdKey = "NYX7-ZEC9-FYZ6-GUX8-4253";
    private const string DefaultPlainCdKey = "NYX7ZEC9FYZ6GUX84253";

    // This installer intentionally ships the same known-good retail-compatible key
    // as the legacy batch bootstrap, so it stays dependency-free on stock Windows.
    private static readonly byte[] DefaultEncryptedCdKey = new byte[]
    {
        0xFB, 0x0F, 0x77, 0xC4, 0x80, 0x3F, 0x65, 0xDB,
        0xBB, 0xA6, 0x6A, 0x4D, 0x4E, 0x2C, 0xB6, 0x17,
    };

    private static readonly byte[] EmbeddedKver = new byte[]
    {
            0x30, 0x82, 0x01, 0xA2, 0x02, 0x81, 0x81, 0x00, 0x8D, 0x75, 0xBA, 0xBB, 0x7C, 0x80, 0x00, 0xF0,
            0xD6, 0xEE, 0xD6, 0x37, 0x89, 0x4A, 0x88, 0x4E, 0x25, 0x17, 0xE4, 0xD6, 0x0E, 0xC9, 0xD1, 0x9D,
            0x3D, 0x87, 0xAC, 0x01, 0x12, 0xB2, 0x82, 0x20, 0xD5, 0x5A, 0xAD, 0x77, 0xC9, 0xE9, 0x14, 0x27,
            0x1F, 0x97, 0x9E, 0x5D, 0xD7, 0x61, 0xC9, 0xC5, 0x69, 0xA5, 0xE4, 0x8A, 0x86, 0x3E, 0x6D, 0xAA,
            0xA3, 0xA6, 0xE4, 0x1E, 0x6A, 0xE7, 0x43, 0x52, 0x90, 0x31, 0x84, 0x44, 0x90, 0x0A, 0x3A, 0x65,
            0x30, 0x6D, 0xDC, 0x31, 0xCF, 0xF5, 0xBF, 0x49, 0x8E, 0xAD, 0x0D, 0x2F, 0x61, 0x65, 0xAB, 0xB0,
            0x8C, 0xA5, 0x0A, 0x6F, 0x89, 0x23, 0x40, 0x94, 0x66, 0xE4, 0x76, 0x0D, 0xDC, 0x19, 0xAC, 0x31,
            0xF9, 0xEB, 0x23, 0xDB, 0x96, 0xEF, 0xF1, 0xEA, 0x43, 0xAE, 0xBE, 0xDE, 0x3C, 0xBB, 0x8A, 0xC9,
            0x6A, 0xF5, 0x92, 0x15, 0x78, 0xB0, 0xB6, 0x7F, 0x02, 0x15, 0x00, 0xC9, 0x33, 0xE6, 0x20, 0x60,
            0x77, 0xFF, 0x5A, 0x12, 0x35, 0x0F, 0xA4, 0xC3, 0x9C, 0x69, 0xC4, 0x47, 0x4B, 0x23, 0x5F, 0x02,
            0x81, 0x80, 0x53, 0x10, 0xA4, 0x97, 0x57, 0xB1, 0x41, 0x43, 0x9C, 0x41, 0x63, 0x0D, 0xF3, 0xCE,
            0xEC, 0x38, 0xA0, 0xAF, 0x72, 0x6B, 0xFA, 0x61, 0x58, 0x72, 0xC4, 0x84, 0xC5, 0x7C, 0xE0, 0x92,
            0x15, 0xDF, 0x4A, 0x2F, 0x19, 0x35, 0x52, 0x86, 0xC6, 0x83, 0x15, 0x77, 0x13, 0x8B, 0x00, 0xF3,
            0xA6, 0xD3, 0x79, 0xB2, 0xD8, 0xFB, 0x2E, 0x53, 0x7E, 0xC5, 0x5A, 0x51, 0x04, 0xD5, 0xD3, 0x96,
            0xC3, 0x4D, 0x62, 0xAC, 0x44, 0xC8, 0xBB, 0x20, 0x68, 0x34, 0x71, 0xEA, 0x2B, 0x01, 0x42, 0xC3,
            0x82, 0x89, 0x6D, 0x79, 0x36, 0x57, 0x1B, 0xE7, 0x48, 0x72, 0x5E, 0x17, 0xE7, 0xEB, 0x70, 0x7A,
            0xF8, 0x42, 0xF4, 0xB5, 0x88, 0xE4, 0x8C, 0x30, 0xE5, 0xD7, 0x1C, 0xED, 0x40, 0x35, 0xE2, 0x18,
            0x7E, 0x88, 0xEB, 0x39, 0x12, 0x5E, 0x40, 0x23, 0x1D, 0x8C, 0x67, 0xB5, 0x00, 0xFC, 0x01, 0x99,
            0x84, 0x8E, 0x02, 0x81, 0x81, 0x00, 0x81, 0xA8, 0x36, 0xB0, 0xA9, 0xF0, 0x1F, 0x1C, 0xC1, 0x16,
            0x1A, 0x65, 0xCD, 0xE2, 0x18, 0xF3, 0xA9, 0x3E, 0x62, 0xCD, 0xA0, 0x51, 0x8C, 0x32, 0xA2, 0x75,
            0xC0, 0xE8, 0x79, 0x83, 0xC9, 0x67, 0x8A, 0xB7, 0xB9, 0x27, 0x1C, 0xA5, 0x40, 0xA0, 0xAF, 0xE8,
            0x02, 0x95, 0x66, 0x4E, 0x04, 0x1A, 0x53, 0x42, 0x52, 0xC7, 0x56, 0xB9, 0x79, 0x6F, 0x35, 0x14,
            0xF5, 0x83, 0xF3, 0x64, 0x01, 0x25, 0xD8, 0x13, 0x04, 0xA4, 0xC4, 0x76, 0xCC, 0xDF, 0xAF, 0x55,
            0x16, 0x06, 0x6C, 0x44, 0x73, 0x0A, 0xA8, 0xA9, 0x18, 0x4D, 0xA1, 0x8C, 0xC4, 0xC2, 0xEF, 0x3A,
            0x68, 0xB1, 0x5F, 0xEA, 0x69, 0xE6, 0x0F, 0x60, 0x2E, 0xBE, 0x55, 0x93, 0xA9, 0x17, 0x4E, 0x2C,
            0x87, 0x70, 0xA1, 0x20, 0x1E, 0x1E, 0x7F, 0x4E, 0x31, 0x38, 0xAD, 0x81, 0x75, 0x65, 0x25, 0x63,
            0x82, 0x19, 0xF3, 0xB8, 0x68, 0x65,
    };

    [STAThread]
    private static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        try
        {
            Run(args);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Homeworld Online Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(1);
        }
    }

    private static void Run(string[] args)
    {
        InstallerOptions options = InstallerOptions.Parse(args);
        string gameDirectory = ResolveGameDirectory(options.GameDirectory, options.Uninstall);

        if (options.Uninstall)
        {
            Uninstall(gameDirectory);
            MessageBox.Show(
                "Homeworld bootstrap settings removed.",
                "Homeworld Online Setup",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (string.IsNullOrEmpty(gameDirectory))
        {
            throw new InvalidOperationException("Could not locate Homeworld.exe.");
        }

        string serverHost = string.IsNullOrWhiteSpace(options.ServerHost)
            ? PromptForServerHost(DefaultServerHost)
            : options.ServerHost.Trim();
        if (string.IsNullOrWhiteSpace(serverHost))
        {
            throw new OperationCanceledException();
        }

        Install(gameDirectory, serverHost);
        MessageBox.Show(
            string.Format(
                "Homeworld configured for server {0}. Launch the game normally.",
                serverHost),
            "Homeworld Online Setup",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private static void Install(string gameDirectory, string serverHost)
    {
        EnsureHomeworldDirectory(gameDirectory);
        WriteRegistryKeys();
        BackupNetTweak(gameDirectory);
        WriteNetTweak(gameDirectory, serverHost);
        File.WriteAllBytes(Path.Combine(gameDirectory, "kver.kp"), EmbeddedKver);
    }

    private static void Uninstall(string gameDirectory)
    {
        RemoveRegistryKeys();
        if (!string.IsNullOrEmpty(gameDirectory))
        {
            DeleteIfExists(Path.Combine(gameDirectory, "NetTweak.script"));
            DeleteIfExists(Path.Combine(gameDirectory, "kver.kp"));
        }
    }

    private static void WriteRegistryKeys()
    {
        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            using (RegistryKey wonKeys = baseKey.CreateSubKey(@"SOFTWARE\WON\CDKeys"))
            {
                if (wonKeys == null)
                {
                    throw new InvalidOperationException("Failed to open HKLM\\SOFTWARE\\WON\\CDKeys.");
                }
                wonKeys.SetValue("Homeworld", DefaultEncryptedCdKey, RegistryValueKind.Binary);
            }

            using (RegistryKey sierraKey = baseKey.CreateSubKey(@"SOFTWARE\Sierra On-Line\Homeworld"))
            {
                if (sierraKey == null)
                {
                    throw new InvalidOperationException("Failed to open HKLM\\SOFTWARE\\Sierra On-Line\\Homeworld.");
                }
                sierraKey.SetValue("CDKey", DefaultPlainCdKey, RegistryValueKind.String);
            }
        }
    }

    private static void RemoveRegistryKeys()
    {
        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            using (RegistryKey wonKeys = baseKey.OpenSubKey(@"SOFTWARE\WON\CDKeys", true))
            {
                if (wonKeys != null)
                {
                    wonKeys.DeleteValue("Homeworld", false);
                }
            }

            using (RegistryKey sierraKey = baseKey.OpenSubKey(@"SOFTWARE\Sierra On-Line\Homeworld", true))
            {
                if (sierraKey != null)
                {
                    sierraKey.DeleteValue("CDKey", false);
                }
            }
        }
    }

    private static void BackupNetTweak(string gameDirectory)
    {
        string netTweakPath = Path.Combine(gameDirectory, "NetTweak.script");
        string backupPath = netTweakPath + ".homeworld_oss.bak";
        if (!File.Exists(netTweakPath) || File.Exists(backupPath))
        {
            return;
        }

        File.Copy(netTweakPath, backupPath, false);
    }

    private static void WriteNetTweak(string gameDirectory, string serverHost)
    {
        string netTweakPath = Path.Combine(gameDirectory, "NetTweak.script");
        string contents = string.Join(
            "\r\n",
            new[]
            {
                "DIRSERVER_NUM 1",
                string.Format("DIRSERVER_PORTS {0}", DefaultGatewayPort),
                string.Format("DIRSERVER_IPSTRINGS {0}", serverHost),
                "PATCHSERVER_NUM 1",
                string.Format("PATCHSERVER_PORTS {0}", DefaultGatewayPort),
                string.Format("PATCHSERVER_IPSTRINGS {0}", serverHost),
                string.Empty,
            });
        File.WriteAllText(netTweakPath, contents, Encoding.ASCII);
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string ResolveGameDirectory(string explicitDirectory, bool optional)
    {
        List<string> candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitDirectory))
        {
            candidates.Add(explicitDirectory);
        }

        string registry64 = ReadInstallPath(RegistryView.Registry64);
        if (!string.IsNullOrEmpty(registry64))
        {
            candidates.Add(registry64);
        }

        string registry32 = ReadInstallPath(RegistryView.Registry32);
        if (!string.IsNullOrEmpty(registry32))
        {
            candidates.Add(registry32);
        }

        candidates.Add(@"C:\Games\Homeworld");
        candidates.Add(@"C:\Program Files (x86)\Sierra\Homeworld");
        candidates.Add(@"C:\Sierra\Homeworld");
        candidates.Add(Environment.CurrentDirectory);

        foreach (string candidate in candidates)
        {
            string normalized = NormalizeGameDirectory(candidate);
            if (!string.IsNullOrEmpty(normalized))
            {
                return normalized;
            }
        }

        string description = optional
            ? "Select the Homeworld folder to remove NetTweak.script and kver.kp (optional)."
            : "Select the Homeworld install folder.";
        return PickGameDirectory(description, optional);
    }

    private static string ReadInstallPath(RegistryView view)
    {
        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
        using (RegistryKey gameKey = baseKey.OpenSubKey(@"SOFTWARE\Sierra On-Line\Homeworld"))
        {
            if (gameKey == null)
            {
                return null;
            }

            object value = gameKey.GetValue("InstallPath");
            return value as string;
        }
    }

    private static string NormalizeGameDirectory(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        string path = candidate.Trim().Trim('"');
        if (File.Exists(path) &&
            string.Equals(Path.GetFileName(path), "Homeworld.exe", StringComparison.OrdinalIgnoreCase))
        {
            path = Path.GetDirectoryName(path);
        }

        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
        {
            return null;
        }

        string exePath = Path.Combine(path, "Homeworld.exe");
        if (!File.Exists(exePath))
        {
            return null;
        }

        return Path.GetFullPath(path);
    }

    private static string PickGameDirectory(string description, bool optional)
    {
        using (FolderBrowserDialog dialog = new FolderBrowserDialog())
        {
            dialog.Description = description;
            dialog.ShowNewFolderButton = false;
            DialogResult result = dialog.ShowDialog();
            if (result != DialogResult.OK)
            {
                if (optional)
                {
                    return null;
                }
                throw new OperationCanceledException();
            }

            string normalized = NormalizeGameDirectory(dialog.SelectedPath);
            if (normalized == null)
            {
                throw new InvalidOperationException("The selected folder does not contain Homeworld.exe.");
            }
            return normalized;
        }
    }

    private static void EnsureHomeworldDirectory(string gameDirectory)
    {
        string normalized = NormalizeGameDirectory(gameDirectory);
        if (normalized == null)
        {
            throw new InvalidOperationException("The selected folder does not contain Homeworld.exe.");
        }
    }

    private static string PromptForServerHost(string defaultValue)
    {
        using (Form form = new Form())
        using (Label label = new Label())
        using (TextBox textBox = new TextBox())
        using (Button okButton = new Button())
        using (Button cancelButton = new Button())
        {
            form.Text = "Homeworld Online Setup";
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.ClientSize = new Size(420, 120);
            form.MinimizeBox = false;
            form.MaximizeBox = false;
            form.AcceptButton = okButton;
            form.CancelButton = cancelButton;

            label.AutoSize = true;
            label.Location = new Point(12, 15);
            label.Text = "Directory/Patch server host:";

            textBox.Location = new Point(15, 40);
            textBox.Size = new Size(390, 23);
            textBox.Text = defaultValue;

            okButton.Text = "OK";
            okButton.Location = new Point(249, 80);
            okButton.DialogResult = DialogResult.OK;

            cancelButton.Text = "Cancel";
            cancelButton.Location = new Point(330, 80);
            cancelButton.DialogResult = DialogResult.Cancel;

            form.Controls.Add(label);
            form.Controls.Add(textBox);
            form.Controls.Add(okButton);
            form.Controls.Add(cancelButton);

            DialogResult result = form.ShowDialog();
            if (result != DialogResult.OK)
            {
                throw new OperationCanceledException();
            }
            return textBox.Text.Trim();
        }
    }

    private sealed class InstallerOptions
    {
        public string ServerHost { get; private set; }
        public string GameDirectory { get; private set; }
        public bool Uninstall { get; private set; }

        public static InstallerOptions Parse(string[] args)
        {
            InstallerOptions options = new InstallerOptions();
            for (int i = 0; i < args.Length; i += 1)
            {
                string arg = args[i];
                if (Matches(arg, "--uninstall", "/uninstall"))
                {
                    options.Uninstall = true;
                    continue;
                }
                if (Matches(arg, "--server", "/server"))
                {
                    options.ServerHost = ReadValue(args, ref i, arg);
                    continue;
                }
                if (Matches(arg, "--game-dir", "/game-dir"))
                {
                    options.GameDirectory = ReadValue(args, ref i, arg);
                    continue;
                }

                if (string.IsNullOrWhiteSpace(options.ServerHost) && !LooksLikePath(arg))
                {
                    options.ServerHost = arg;
                    continue;
                }
                if (string.IsNullOrWhiteSpace(options.GameDirectory))
                {
                    options.GameDirectory = arg;
                    continue;
                }

                throw new ArgumentException("Too many arguments.");
            }
            return options;
        }

        private static bool Matches(string arg, string longForm, string shortForm)
        {
            return string.Equals(arg, longForm, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(arg, shortForm, StringComparison.OrdinalIgnoreCase);
        }

        private static string ReadValue(string[] args, ref int index, string optionName)
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException(string.Format("Missing value for {0}.", optionName));
            }
            index += 1;
            return args[index];
        }

        private static bool LooksLikePath(string arg)
        {
            return arg.IndexOf('\\') >= 0 || arg.IndexOf('/') >= 0 || arg.IndexOf(':') >= 0;
        }
    }
}
