using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class HWClientSetup
{
    private const string CustomHostOptionLabel = "Custom host or IP";
    private const int DefaultGatewayPort = 15101;
    private const string WonCdKeysRegistryPath = @"SOFTWARE\WON\CDKeys";
    private const string SierraCdKeyValueName = "CDKey";
    private const string SierraDataValueName = "HW_Data";

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

    private static readonly KeyValuePair<string, string>[] NetTweakServerOverrides = new KeyValuePair<string, string>[]
    {
        new KeyValuePair<string, string>("DIRSERVER_NUM", "1"),
        new KeyValuePair<string, string>("DIRSERVER_PORTS", DefaultGatewayPort.ToString()),
        new KeyValuePair<string, string>("PATCHSERVER_NUM", "1"),
        new KeyValuePair<string, string>("PATCHSERVER_PORTS", DefaultGatewayPort.ToString()),
    };

    private static readonly string[] HomeworldRetailNetTweakTemplate = new[]
    {
        "[NetTweak]",
        "TITAN_PICKER_REFRESH_TIME       4.0",
        "TITAN_GAME_EXPIRE_TIME          3600",
        "",
        "GAME_PORT                       6037",
        "",
        "AD_PORT                         6038",
        "",
        "; Main servers",
        "DIRSERVER_NUM                   3",
        "",
        "DIRSERVER_PORTS                 15101,15101,15101",
        "DIRSERVER_IPSTRINGS             homeworld-demo.east.won.net,homeworld-demo.west.won.net,homeworld.central.won.net",
        "",
        "PATCHSERVER_NUM                 1",
        "",
        "PATCHSERVER_PORTS               80",
        "PATCHSERVER_IPSTRINGS           homeworld.update.won.net",
        "",
        "PATCHNAME                       HomeworldPatch.exe",
        "",
        "PATCHBARCOLOR                   255,0,0",
        "PATCHBAROUTLINECOLOR            255,255,0",
        "",
        "ROUTING_SERVER_NAME              routingserv",
        "",
        "CONNECT_TIMEOUT                  8000    ; timeout for connects in ms",
        "",
        "; Passing captaincy tweakables:",
        "",
        "T1_Timeout                       30.0       ; timeout for not receiving any packets from captain",
        "T2_Timeout                       14.0        ; timeout for proposing a new captain",
        "TWAITFORPAUSEACKS_Timeout        14.0        ; timeout for waiting for pause ack's from remaining players",
        "",
        "TimedOutWaitingForPauseAcksGiveUpAfterNumTimes   2       ; after this many time outs while waiting for pause acks, give up waiting",
        "",
        "HorseRacePlayerDropoutTime       40.0",
        "HorseRaceDroppedOutColor         75,75,75",
        "",
        "; Lan tweakables",
        "",
        "LAN_ADVERTISE_USER_TIME          0.5",
        "LAN_ADVERTISE_USER_TIMEOUT       3.0",
        "",
        "LAN_ADVERTISE_GAME_TIME          0.5",
        "LAN_ADVERTISE_GAME_TIMEOUT       3.0",
        "",
        "; Keep alive tweakables (know if player is still actively in game)",
        "",
        "KEEPALIVE_SEND_IAMALIVE_TIME    10.0",
        "KEEPALIVE_IAMALIVE_TIMEOUT      30.0",
        "KEEPALIVE_SEND_ALIVESTATUS_TIME 30.0",
        "",
        "PRINTLAG_IFGREATERTHAN          10          ; make really big to turn off",
        "PRINTLAG_MINFRAMES              20",
        "",
        "ROOM_MIN_THRESHOLD              1",
        "ROOM_MAX_THRESHOLD              30",
        "",
        "WAIT_SHUTDOWN_MS                1000        ; if you have created a game and quit won, wait this long before quitting so the messages to dissolve, etc, get sent.",
    };

    private static readonly string[] CataclysmRetailNetTweakTemplate = new[]
    {
        "[NetTweak]",
        "TITAN_PICKER_REFRESH_TIME       4.0",
        "TITAN_GAME_EXPIRE_TIME          3600",
        "",
        "GAME_PORT                       6037",
        "",
        "AD_PORT                         6038",
        "",
        "; Main servers",
        "DIRSERVER_NUM                   3",
        "",
        "DIRSERVER_PORTS                 15101,15101,15101",
        "DIRSERVER_IPSTRINGS             cataclysm.east.won.net,cataclysm.west.won.net,cataclysm.central.won.net",
        "",
        "PATCHSERVER_NUM                 1",
        "",
        "PATCHSERVER_PORTS               80",
        "PATCHSERVER_IPSTRINGS           cataclysm.central.won.net",
        "",
        "PATCHNAME                       HomeworldPatch.exe",
        "",
        "PATCHBARCOLOR                   255,0,0",
        "PATCHBAROUTLINECOLOR            255,255,0",
        "",
        "ROUTING_SERVER_NAME              routingserv",
        "",
        "CONNECT_TIMEOUT                  8000    ; timeout for connects in ms",
        "",
        "; Passing captaincy tweakables:",
        "",
        "T1_Timeout                       30.0       ; timeout for not receiving any packets from captain",
        "T2_Timeout                       14.0        ; timeout for proposing a new captain",
        "TWAITFORPAUSEACKS_Timeout        14.0        ; timeout for waiting for pause ack's from remaining players",
        "",
        "TimedOutWaitingForPauseAcksGiveUpAfterNumTimes   2       ; after this many time outs while waiting for pause acks, give up waiting",
        "",
        "HorseRacePlayerDropoutTime       40.0",
        "HorseRaceDroppedOutColor         75,75,75",
        "",
        "; Lan tweakables",
        "",
        "LAN_ADVERTISE_USER_TIME          0.5",
        "LAN_ADVERTISE_USER_TIMEOUT       3.0",
        "",
        "LAN_ADVERTISE_GAME_TIME          0.5",
        "LAN_ADVERTISE_GAME_TIMEOUT       3.0",
        "",
        "; Keep alive tweakables (know if player is still actively in game)",
        "",
        "KEEPALIVE_SEND_IAMALIVE_TIME    10.0",
        "KEEPALIVE_IAMALIVE_TIMEOUT      30.0",
        "KEEPALIVE_SEND_ALIVESTATUS_TIME 30.0",
        "",
        "PRINTLAG_IFGREATERTHAN          10          ; make really big to turn off",
        "PRINTLAG_MINFRAMES              20",
        "",
        "ROOM_MIN_THRESHOLD              1",
        "ROOM_MAX_THRESHOLD              30",
        "",
        "WAIT_SHUTDOWN_MS                1000        ; if you have created a game and quit won, wait this long before quitting so the messages to dissolve, etc, get sent.",
    };

    private sealed class GameInstallConfig
    {
        public GameInstallConfig(
            string key,
            string displayName,
            string windowTitle,
            string defaultServerHost,
            string netTweakBackupSuffix,
            string retailProductName,
            string defaultDisplayCdKey,
            byte[] defaultEncryptedCdKey,
            string sierraRegistryPath,
            string wonRegistryValueName,
            string installerRegistryMarkerValueName,
            string[] supportedExecutableNames,
            string[] defaultInstallDirectories,
            string[] retailNetTweakTemplate,
            bool experimentalRegistry,
            string sierraVirtualStoreRegistryPath,
            string sierraVersionSubkeyName)
        {
            Key = key;
            DisplayName = displayName;
            WindowTitle = windowTitle;
            DefaultServerHost = defaultServerHost;
            NetTweakBackupSuffix = netTweakBackupSuffix;
            RetailProductName = retailProductName;
            DefaultDisplayCdKey = defaultDisplayCdKey;
            DefaultEncryptedCdKey = defaultEncryptedCdKey;
            SierraRegistryPath = sierraRegistryPath;
            WonRegistryValueName = wonRegistryValueName;
            InstallerRegistryMarkerValueName = installerRegistryMarkerValueName;
            SupportedExecutableNames = supportedExecutableNames;
            DefaultInstallDirectories = defaultInstallDirectories;
            RetailNetTweakTemplate = retailNetTweakTemplate;
            ExperimentalRegistry = experimentalRegistry;
            SierraVirtualStoreRegistryPath = sierraVirtualStoreRegistryPath;
            SierraVersionSubkeyName = sierraVersionSubkeyName;
        }

        public string Key { get; private set; }
        public string DisplayName { get; private set; }
        public string WindowTitle { get; private set; }
        public string DefaultServerHost { get; private set; }
        public string NetTweakBackupSuffix { get; private set; }
        public string RetailProductName { get; private set; }
        public string DefaultDisplayCdKey { get; private set; }
        public byte[] DefaultEncryptedCdKey { get; private set; }
        public string SierraRegistryPath { get; private set; }
        public string WonRegistryValueName { get; private set; }
        public string InstallerRegistryMarkerValueName { get; private set; }
        public string[] SupportedExecutableNames { get; private set; }
        public string[] DefaultInstallDirectories { get; private set; }
        public string[] RetailNetTweakTemplate { get; private set; }
        public bool ExperimentalRegistry { get; private set; }
        public string SierraVirtualStoreRegistryPath { get; private set; }
        public string SierraVersionSubkeyName { get; private set; }

        public bool HasVirtualStore
        {
            get { return !string.IsNullOrWhiteSpace(SierraVirtualStoreRegistryPath); }
        }

        public bool HasVersionSubkey
        {
            get { return !string.IsNullOrWhiteSpace(SierraVersionSubkeyName); }
        }
    }

    private static readonly GameInstallConfig HomeworldGame = new GameInstallConfig(
        key: "homeworld",
        displayName: "Homeworld",
        windowTitle: "Homeworld Online Setup",
        defaultServerHost: "homeworld.kerrbell.dev",
        netTweakBackupSuffix: ".homeworld_oss.bak",
        retailProductName: "Homeworld",
        defaultDisplayCdKey: "NYX7-ZEC9-FYZ6-GUX8-4253",
        defaultEncryptedCdKey: new byte[]
        {
            0xFB, 0x0F, 0x77, 0xC4, 0x80, 0x3F, 0x65, 0xDB,
            0xBB, 0xA6, 0x6A, 0x4D, 0x4E, 0x2C, 0xB6, 0x17,
        },
        sierraRegistryPath: @"SOFTWARE\Sierra On-Line\Homeworld",
        wonRegistryValueName: "Homeworld",
        installerRegistryMarkerValueName: "HomeworldOnlineSetupWroteCdKey",
        supportedExecutableNames: new[] { "Homeworld.exe" },
        defaultInstallDirectories: new[]
        {
            @"C:\Games\Homeworld",
            @"C:\Program Files (x86)\Sierra\Homeworld",
            @"C:\Sierra\Homeworld",
        },
        retailNetTweakTemplate: HomeworldRetailNetTweakTemplate,
        experimentalRegistry: false,
        sierraVirtualStoreRegistryPath: null,
        sierraVersionSubkeyName: null
    );

    private static readonly GameInstallConfig CataclysmGame = new GameInstallConfig(
        key: "cataclysm",
        displayName: "Homeworld: Cataclysm",
        windowTitle: "Homeworld: Cataclysm Online Setup",
        defaultServerHost: "cataclysm.kerrbell.dev",
        netTweakBackupSuffix: ".cataclysm_oss.bak",
        retailProductName: "Cataclysm",
        defaultDisplayCdKey: "GAF6-CAB4-SEX5-ZYL6-2622",
        defaultEncryptedCdKey: new byte[]
        {
            0x85, 0x05, 0xE4, 0x99, 0xD8, 0xC1, 0x80, 0x62,
            0x31, 0x8D, 0xA4, 0x99, 0x90, 0xD8, 0x69, 0x8E,
        },
        sierraRegistryPath: @"SOFTWARE\Sierra On-Line\Cataclysm",
        wonRegistryValueName: "Cataclysm",
        installerRegistryMarkerValueName: "CataclysmOnlineSetupWroteCdKey",
        supportedExecutableNames: new[] { "Cataclysm.exe", "HomeworldCataclysm.exe", "Homeworld.exe" },
        defaultInstallDirectories: new[]
        {
            @"C:\Games\Cataclysm",
            @"C:\Program Files (x86)\Sierra\Cataclysm",
            @"C:\Sierra\Cataclysm",
            @"C:\GOG Games\Homeworld Emergence",
            @"C:\GOG Games\Homeworld Cataclysm",
        },
        retailNetTweakTemplate: CataclysmRetailNetTweakTemplate,
        experimentalRegistry: true,
        sierraVirtualStoreRegistryPath: @"SOFTWARE\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Sierra On-Line\Cataclysm",
        sierraVersionSubkeyName: "1.0.0.0"
    );

    private static readonly GameInstallConfig[] KnownGames = new[]
    {
        HomeworldGame,
        CataclysmGame,
    };

    private static GameInstallConfig CurrentGame = HomeworldGame;

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
                CurrentGame.WindowTitle,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            Environment.Exit(1);
        }
    }

    private static void Run(string[] args)
    {
        InstallerOptions options = InstallerOptions.Parse(args);
        CurrentGame = ResolveGameConfig(options);
        string gameDirectory = ResolveGameDirectory(options.GameDirectory, options.Uninstall);

        if (options.Uninstall)
        {
            Uninstall(gameDirectory);
            MessageBox.Show(
                CurrentGame.DisplayName + " bootstrap settings removed.",
                CurrentGame.WindowTitle,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (string.IsNullOrEmpty(gameDirectory))
        {
            throw new InvalidOperationException("Could not locate a supported " + CurrentGame.DisplayName + " executable.");
        }

        ExistingInstallState existingState = DetectExistingInstallState(gameDirectory);
        bool shouldRefreshInstallerOwnedKey = existingState.HasAnyRegistryCdKey && existingState.RegistryOwnedByInstaller;
        bool defaultWriteRegistryKeys = options.WriteRegistryKeys ?? (!existingState.HasAnyRegistryCdKey || shouldRefreshInstallerOwnedKey);

        // Generate a unique random key by default so users don't all share the
        // same hardcoded key.  The known-good default is only used as a self-test
        // for the keygen (validated inside GetDefaultRegistryCdKey).
        GetDefaultRegistryCdKey(); // self-test only
        RegistryCdKeyOption initialCdKey = PickRandomRegistryCdKey(existingState.SierraCdKeyDisplay);

        InstallChoices installChoices = string.IsNullOrWhiteSpace(options.ServerHost)
            ? PromptForInstallChoices(CurrentGame.DefaultServerHost, defaultWriteRegistryKeys, initialCdKey, existingState)
            : new InstallChoices
            {
                ServerHost = options.ServerHost.Trim(),
                WriteRegistryKeys = defaultWriteRegistryKeys,
                RegistryCdKey = initialCdKey,
            };

        if (string.IsNullOrWhiteSpace(installChoices.ServerHost))
        {
            throw new OperationCanceledException();
        }

        installChoices.ServerHost = NormalizeServerHost(installChoices.ServerHost);

        InstallResult result = Install(gameDirectory, installChoices.ServerHost, installChoices.WriteRegistryKeys, installChoices.RegistryCdKey);
        MessageBox.Show(
            BuildInstallSuccessMessage(result),
            CurrentGame.WindowTitle,
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private static InstallResult Install(string gameDirectory, string serverHost, bool writeRegistryKeys, RegistryCdKeyOption registryCdKey)
    {
        EnsureSelectedGameDirectory(gameDirectory);
        RegistryWriteResult registryWriteResult = null;
        if (writeRegistryKeys)
        {
            registryWriteResult = WriteRegistryKeys(gameDirectory, registryCdKey ?? GetDefaultRegistryCdKey());
        }
        BackupNetTweak(gameDirectory);
        WriteNetTweak(gameDirectory, serverHost);
        WriteFileBytes(Path.Combine(gameDirectory, "kver.kp"), EmbeddedKver, "kver.kp");

        return new InstallResult
        {
            ServerHost = serverHost,
            RegistryWrite = registryWriteResult,
        };
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

    private static RegistryWriteResult WriteRegistryKeys(string gameDirectory, RegistryCdKeyOption registryCdKey)
    {
        string normalizedGameDirectory = Path.GetFullPath(gameDirectory);
        string sierraVersionRegistryPath = CurrentGame.HasVersionSubkey
            ? CurrentGame.SierraRegistryPath + "\\" + CurrentGame.SierraVersionSubkeyName
            : null;

        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            using (RegistryKey wonKeys = baseKey.CreateSubKey(WonCdKeysRegistryPath))
            {
                if (wonKeys == null)
                {
                    throw new InvalidOperationException("Failed to open HKLM\\" + WonCdKeysRegistryPath + ".");
                }
                wonKeys.SetValue(CurrentGame.WonRegistryValueName, registryCdKey.EncryptedCdKey, RegistryValueKind.Binary);
            }

            using (RegistryKey sierraKey = baseKey.CreateSubKey(CurrentGame.SierraRegistryPath))
            {
                if (sierraKey == null)
                {
                    throw new InvalidOperationException("Failed to open HKLM\\" + CurrentGame.SierraRegistryPath + ".");
                }
                sierraKey.SetValue(SierraCdKeyValueName, registryCdKey.PlainCdKey, RegistryValueKind.String);
                if (CurrentGame.HasVirtualStore && string.IsNullOrWhiteSpace(sierraKey.GetValue(SierraDataValueName) as string))
                {
                    sierraKey.SetValue(SierraDataValueName, normalizedGameDirectory, RegistryValueKind.String);
                }
                sierraKey.SetValue(CurrentGame.InstallerRegistryMarkerValueName, 1, RegistryValueKind.DWord);
            }

            if (CurrentGame.HasVersionSubkey)
            {
                using (RegistryKey versionKey = baseKey.CreateSubKey(sierraVersionRegistryPath))
                {
                    if (versionKey == null)
                    {
                        throw new InvalidOperationException("Failed to open HKLM\\" + sierraVersionRegistryPath + ".");
                    }
                    if (versionKey.GetValue(null) == null)
                    {
                        versionKey.SetValue(string.Empty, string.Empty, RegistryValueKind.String);
                    }
                }
            }
        }

        if (CurrentGame.HasVirtualStore)
        {
            using (RegistryKey currentUserKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (RegistryKey virtualStoreKey = currentUserKey.CreateSubKey(CurrentGame.SierraVirtualStoreRegistryPath))
            {
                if (virtualStoreKey == null)
                {
                    throw new InvalidOperationException("Failed to open HKCU\\" + CurrentGame.SierraVirtualStoreRegistryPath + ".");
                }

                virtualStoreKey.SetValue(SierraCdKeyValueName, registryCdKey.PlainCdKey, RegistryValueKind.String);
                if (string.IsNullOrWhiteSpace(virtualStoreKey.GetValue(SierraDataValueName) as string))
                {
                    virtualStoreKey.SetValue(SierraDataValueName, normalizedGameDirectory, RegistryValueKind.String);
                }
                virtualStoreKey.SetValue(CurrentGame.InstallerRegistryMarkerValueName, 1, RegistryValueKind.DWord);
            }
        }

        return new RegistryWriteResult
        {
            DisplayCdKey = registryCdKey.DisplayCdKey,
            SierraRegistryValuePath = @"HKLM\" + CurrentGame.SierraRegistryPath + "\\" + SierraCdKeyValueName,
            SierraDataValuePath = CurrentGame.HasVirtualStore
                ? @"HKLM\" + CurrentGame.SierraRegistryPath + "\\" + SierraDataValueName
                : null,
            SierraVersionKeyPath = sierraVersionRegistryPath == null
                ? null
                : @"HKLM\" + sierraVersionRegistryPath,
            VirtualStoreRegistryValuePath = CurrentGame.HasVirtualStore
                ? @"HKCU\" + CurrentGame.SierraVirtualStoreRegistryPath + "\\" + SierraCdKeyValueName
                : null,
            WonRegistryValuePath = @"HKLM\" + WonCdKeysRegistryPath + "\\" + CurrentGame.WonRegistryValueName,
        };
    }

    private static void RemoveRegistryKeys()
    {
        bool ownsAnyRegistryKeys = false;

        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            using (RegistryKey sierraKey = baseKey.OpenSubKey(CurrentGame.SierraRegistryPath, true))
            {
                if (InstallerOwnsRegistryKeys(sierraKey))
                {
                    ownsAnyRegistryKeys = true;
                    sierraKey.DeleteValue(SierraCdKeyValueName, false);
                    sierraKey.DeleteValue(CurrentGame.InstallerRegistryMarkerValueName, false);
                }
            }

            using (RegistryKey wonKeys = baseKey.OpenSubKey(WonCdKeysRegistryPath, true))
            {
                if (wonKeys != null && ownsAnyRegistryKeys && !CurrentGame.HasVirtualStore)
                {
                    wonKeys.DeleteValue(CurrentGame.WonRegistryValueName, false);
                }
            }
        }

        if (CurrentGame.HasVirtualStore)
        {
            using (RegistryKey currentUserKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (RegistryKey virtualStoreKey = currentUserKey.OpenSubKey(CurrentGame.SierraVirtualStoreRegistryPath, true))
            {
                if (InstallerOwnsRegistryKeys(virtualStoreKey))
                {
                    ownsAnyRegistryKeys = true;
                    virtualStoreKey.DeleteValue(SierraCdKeyValueName, false);
                    virtualStoreKey.DeleteValue(CurrentGame.InstallerRegistryMarkerValueName, false);
                }
            }
        }

        if (!ownsAnyRegistryKeys)
        {
            return;
        }

        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        using (RegistryKey wonKeys = baseKey.OpenSubKey(WonCdKeysRegistryPath, true))
        {
            if (wonKeys != null)
            {
                wonKeys.DeleteValue(CurrentGame.WonRegistryValueName, false);
            }
        }
    }

    private static bool InstallerOwnsRegistryKeys(RegistryKey sierraKey)
    {
        if (sierraKey == null)
        {
            return false;
        }

        object markerValue = sierraKey.GetValue(CurrentGame.InstallerRegistryMarkerValueName);
        if (markerValue is int)
        {
            return (int)markerValue == 1;
        }

        if (markerValue is string)
        {
            int parsed;
            if (int.TryParse((string)markerValue, out parsed))
            {
                return parsed == 1;
            }
        }

        return false;
    }

    private static void BackupNetTweak(string gameDirectory)
    {
        string netTweakPath = Path.Combine(gameDirectory, "NetTweak.script");
        string backupPath = netTweakPath + CurrentGame.NetTweakBackupSuffix;
        if (!File.Exists(netTweakPath) || File.Exists(backupPath))
        {
            return;
        }

        CopyFile(netTweakPath, backupPath, "NetTweak.script backup");
    }

    private static void WriteNetTweak(string gameDirectory, string serverHost)
    {
        string netTweakPath = Path.Combine(gameDirectory, "NetTweak.script");
        string contents = ApplyNetTweakOverrides(ReadNetTweakBaseline(gameDirectory), serverHost);
        WriteFileText(netTweakPath, contents, Encoding.ASCII, "NetTweak.script");
    }

    private static string ReadNetTweakBaseline(string gameDirectory)
    {
        string netTweakPath = Path.Combine(gameDirectory, "NetTweak.script");
        string backupPath = netTweakPath + CurrentGame.NetTweakBackupSuffix;

        if (File.Exists(backupPath))
        {
            return File.ReadAllText(backupPath, Encoding.ASCII);
        }

        if (File.Exists(netTweakPath))
        {
            return File.ReadAllText(netTweakPath, Encoding.ASCII);
        }

        return string.Join("\r\n", CurrentGame.RetailNetTweakTemplate) + "\r\n";
    }

    private static string ApplyNetTweakOverrides(string baseline, string serverHost)
    {
        Dictionary<string, string> overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string> entry in NetTweakServerOverrides)
        {
            overrides[entry.Key] = entry.Value;
        }

        overrides["DIRSERVER_IPSTRINGS"] = serverHost;
        overrides["PATCHSERVER_IPSTRINGS"] = serverHost;

        List<string> mergedLines = new List<string>();
        HashSet<string> seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string[] baselineLines = baseline
            .Replace("\r\n", "\n")
            .Replace('\r', '\n')
            .Split(new[] { '\n' }, StringSplitOptions.None);

        foreach (string line in baselineLines)
        {
            string key;
            if (TryGetNetTweakKey(line, out key) && overrides.ContainsKey(key))
            {
                mergedLines.Add(string.Format("{0} {1}", key, overrides[key]));
                seenKeys.Add(key);
            }
            else
            {
                mergedLines.Add(line);
            }
        }

        foreach (KeyValuePair<string, string> entry in overrides)
        {
            if (!seenKeys.Contains(entry.Key))
            {
                mergedLines.Add(string.Format("{0} {1}", entry.Key, entry.Value));
            }
        }

        return string.Join("\r\n", mergedLines) + "\r\n";
    }

    private static string NormalizeServerHost(string serverHost)
    {
        string normalized = (serverHost ?? string.Empty).Trim();
        if (normalized.Length == 0)
        {
            throw new InvalidOperationException("Enter a server host or IPv4 address.");
        }

        if (normalized.IndexOfAny(new[] { '\r', '\n', '\t', ' ', ',', ';', '"', '\'' }) >= 0)
        {
            throw new InvalidOperationException("Server host must be a single hostname or IPv4 address without spaces or control characters.");
        }

        foreach (char ch in normalized)
        {
            bool allowed = (ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9')
                || ch == '.'
                || ch == '-';
            if (!allowed)
            {
                throw new InvalidOperationException("Server host contains unsupported characters. Use a hostname like hw1.example.com or an IPv4 address.");
            }
        }

        UriHostNameType hostType = Uri.CheckHostName(normalized);
        if (hostType != UriHostNameType.Dns && hostType != UriHostNameType.IPv4)
        {
            throw new InvalidOperationException("Server host must be a valid hostname or IPv4 address.");
        }

        return normalized;
    }

    private static bool TryGetNetTweakKey(string line, out string key)
    {
        key = null;
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        string trimmed = line.TrimStart();
        if (trimmed.Length == 0 || trimmed[0] == ';' || trimmed[0] == '[')
        {
            return false;
        }

        int end = 0;
        while (end < trimmed.Length && !char.IsWhiteSpace(trimmed[end]))
        {
            end++;
        }

        if (end == 0)
        {
            return false;
        }

        key = trimmed.Substring(0, end);
        return true;
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            try
            {
                File.Delete(path);
            }
            catch (Exception ex)
            {
                if (!(ex is IOException) && !(ex is UnauthorizedAccessException))
                {
                    throw;
                }
                throw new InvalidOperationException("Could not remove " + Path.GetFileName(path) + " at " + path + ". Close any programs using the file and try again.", ex);
            }
        }
    }

    private static void CopyFile(string sourcePath, string destinationPath, string displayName)
    {
        try
        {
            File.Copy(sourcePath, destinationPath, false);
        }
        catch (Exception ex)
        {
            if (!(ex is IOException) && !(ex is UnauthorizedAccessException))
            {
                throw;
            }
            throw new InvalidOperationException("Could not create " + displayName + " at " + destinationPath + ".", ex);
        }
    }

    private static void WriteFileText(string path, string contents, Encoding encoding, string displayName)
    {
        try
        {
            File.WriteAllText(path, contents, encoding);
        }
        catch (Exception ex)
        {
            if (!(ex is IOException) && !(ex is UnauthorizedAccessException))
            {
                throw;
            }
            throw new InvalidOperationException("Could not write " + displayName + " at " + path + ".", ex);
        }
    }

    private static void WriteFileBytes(string path, byte[] contents, string displayName)
    {
        try
        {
            File.WriteAllBytes(path, contents);
        }
        catch (Exception ex)
        {
            if (!(ex is IOException) && !(ex is UnauthorizedAccessException))
            {
                throw;
            }
            throw new InvalidOperationException("Could not write " + displayName + " at " + path + ".", ex);
        }
    }

    private static GameInstallConfig ResolveGameConfig(InstallerOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.GameKey))
        {
            return FindGameByKey(options.GameKey);
        }

        if (!string.IsNullOrWhiteSpace(options.GameDirectory))
        {
            GameInstallConfig fromPath = DetectGameConfigFromPath(options.GameDirectory);
            if (fromPath != null)
            {
                return fromPath;
            }
        }

        List<GameInstallConfig> detected = new List<GameInstallConfig>();
        foreach (GameInstallConfig game in KnownGames)
        {
            if (!string.IsNullOrEmpty(TryResolveGameDirectory(game, null, false, false)))
            {
                detected.Add(game);
            }
        }

        if (detected.Count == 1)
        {
            return detected[0];
        }

        return PromptForGameSelection(detected.Count > 0 ? detected.ToArray() : KnownGames);
    }

    private static GameInstallConfig FindGameByKey(string key)
    {
        foreach (GameInstallConfig game in KnownGames)
        {
            if (string.Equals(game.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                return game;
            }
        }

        throw new ArgumentException("Unknown game selection: " + key + ".");
    }

    private static GameInstallConfig DetectGameConfigFromPath(string candidate)
    {
        foreach (GameInstallConfig game in KnownGames)
        {
            if (!string.IsNullOrEmpty(NormalizeGameDirectory(game, candidate)))
            {
                return game;
            }
        }
        return null;
    }

    private static GameInstallConfig PromptForGameSelection(IList<GameInstallConfig> options)
    {
        if (options == null || options.Count == 0)
        {
            throw new InvalidOperationException("No supported games are configured.");
        }

        if (options.Count == 1)
        {
            return options[0];
        }

        using (Form form = new Form())
        using (Label headingLabel = new Label())
        using (Label summaryLabel = new Label())
        using (ComboBox gameCombo = new ComboBox())
        using (Button okButton = new Button())
        using (Button cancelButton = new Button())
        {
            form.Text = "Retail WON Online Setup";
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.MaximizeBox = false;
            form.MinimizeBox = false;
            form.ClientSize = new Size(400, 170);
            form.Font = SystemFonts.MessageBoxFont;
            form.AcceptButton = okButton;
            form.CancelButton = cancelButton;

            headingLabel.AutoSize = true;
            headingLabel.Font = new Font(form.Font, FontStyle.Bold);
            headingLabel.Location = new Point(15, 15);
            headingLabel.Text = "Select game";

            summaryLabel.AutoSize = false;
            summaryLabel.Location = new Point(15, 38);
            summaryLabel.Size = new Size(370, 34);
            summaryLabel.Text = "Multiple supported games were detected. Choose which one to configure.";

            gameCombo.DropDownStyle = ComboBoxStyle.DropDownList;
            gameCombo.Location = new Point(15, 80);
            gameCombo.Size = new Size(368, 24);
            gameCombo.TabIndex = 0;
            foreach (GameInstallConfig game in options)
            {
                gameCombo.Items.Add(game.DisplayName);
            }
            gameCombo.SelectedIndex = 0;

            okButton.Text = "Continue";
            okButton.Location = new Point(204, 126);
            okButton.Size = new Size(84, 28);
            okButton.DialogResult = DialogResult.OK;
            okButton.TabIndex = 1;

            cancelButton.Text = "Cancel";
            cancelButton.Location = new Point(296, 126);
            cancelButton.Size = new Size(84, 28);
            cancelButton.DialogResult = DialogResult.Cancel;
            cancelButton.TabIndex = 2;

            form.Controls.Add(headingLabel);
            form.Controls.Add(summaryLabel);
            form.Controls.Add(gameCombo);
            form.Controls.Add(okButton);
            form.Controls.Add(cancelButton);

            DialogResult result = form.ShowDialog();
            if (result != DialogResult.OK)
            {
                throw new OperationCanceledException();
            }

            return options[gameCombo.SelectedIndex];
        }
    }

    private static string ResolveGameDirectory(string explicitDirectory, bool optional)
    {
        return TryResolveGameDirectory(CurrentGame, explicitDirectory, optional, true);
    }

    private static string TryResolveGameDirectory(GameInstallConfig game, string explicitDirectory, bool optional, bool promptIfMissing)
    {
        List<string> candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitDirectory))
        {
            candidates.Add(explicitDirectory);
        }

        string registry64 = ReadInstallPath(game, RegistryView.Registry64);
        if (!string.IsNullOrEmpty(registry64))
        {
            candidates.Add(registry64);
        }

        string registry32 = ReadInstallPath(game, RegistryView.Registry32);
        if (!string.IsNullOrEmpty(registry32))
        {
            candidates.Add(registry32);
        }

        string virtualStorePath = ReadVirtualStoreInstallPath(game);
        if (!string.IsNullOrEmpty(virtualStorePath))
        {
            candidates.Add(virtualStorePath);
        }

        foreach (string defaultDirectory in game.DefaultInstallDirectories)
        {
            candidates.Add(defaultDirectory);
        }
        candidates.Add(Environment.CurrentDirectory);

        foreach (string candidate in candidates)
        {
            string normalized = NormalizeGameDirectory(game, candidate);
            if (!string.IsNullOrEmpty(normalized))
            {
                return normalized;
            }
        }

        if (!promptIfMissing)
        {
            return null;
        }

        string description = optional
            ? "Select the " + game.DisplayName + " folder to remove NetTweak.script and kver.kp (optional)."
            : "Select the " + game.DisplayName + " install folder.";
        return PickGameDirectory(game, description, optional);
    }

    private static string ReadInstallPath(GameInstallConfig game, RegistryView view)
    {
        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
        using (RegistryKey gameKey = baseKey.OpenSubKey(game.SierraRegistryPath))
        {
            if (gameKey == null)
            {
                return null;
            }

            string installPath = gameKey.GetValue("InstallPath") as string;
            if (!string.IsNullOrWhiteSpace(installPath))
            {
                return installPath;
            }

            string hwData = gameKey.GetValue(SierraDataValueName) as string;
            if (!string.IsNullOrWhiteSpace(hwData))
            {
                return hwData;
            }

            return null;
        }
    }

    private static string ReadVirtualStoreInstallPath(GameInstallConfig game)
    {
        if (!game.HasVirtualStore)
        {
            return null;
        }

        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
        using (RegistryKey gameKey = baseKey.OpenSubKey(game.SierraVirtualStoreRegistryPath))
        {
            if (gameKey == null)
            {
                return null;
            }

            string hwData = gameKey.GetValue(SierraDataValueName) as string;
            if (!string.IsNullOrWhiteSpace(hwData))
            {
                return hwData;
            }

            string installPath = gameKey.GetValue("InstallPath") as string;
            if (!string.IsNullOrWhiteSpace(installPath))
            {
                return installPath;
            }

            return null;
        }
    }

    private static string FindSupportedExecutablePath(GameInstallConfig game, string directoryPath)
    {
        foreach (string candidate in game.SupportedExecutableNames)
        {
            string exePath = Path.Combine(directoryPath, candidate);
            if (File.Exists(exePath))
            {
                return exePath;
            }
        }

        return null;
    }

    private static string NormalizeGameDirectory(GameInstallConfig game, string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        string path = candidate.Trim().Trim('"');
        if (File.Exists(path))
        {
            foreach (string executableName in game.SupportedExecutableNames)
            {
                if (string.Equals(Path.GetFileName(path), executableName, StringComparison.OrdinalIgnoreCase))
                {
                    path = Path.GetDirectoryName(path);
                    break;
                }
            }
        }

        if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
        {
            return null;
        }

        if (FindSupportedExecutablePath(game, path) == null)
        {
            return null;
        }

        return Path.GetFullPath(path);
    }

    private static string NormalizeGameDirectory(string candidate)
    {
        return NormalizeGameDirectory(CurrentGame, candidate);
    }

    private static string PickGameDirectory(GameInstallConfig game, string description, bool optional)
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

            string normalized = NormalizeGameDirectory(game, dialog.SelectedPath);
            if (normalized == null)
            {
                throw new InvalidOperationException("The selected folder does not contain a supported " + game.DisplayName + " executable.");
            }
            return normalized;
        }
    }

    private static void EnsureSelectedGameDirectory(string gameDirectory)
    {
        string normalized = NormalizeGameDirectory(gameDirectory);
        if (normalized == null)
        {
            throw new InvalidOperationException("The selected folder does not contain a supported " + CurrentGame.DisplayName + " executable.");
        }
    }

    private static ExistingInstallState DetectExistingInstallState(string gameDirectory)
    {
        ExistingInstallState state = new ExistingInstallState();

        if (!string.IsNullOrEmpty(gameDirectory))
        {
            state.HasNetTweakScript = File.Exists(Path.Combine(gameDirectory, "NetTweak.script"));
            state.HasNetTweakBackup = File.Exists(Path.Combine(gameDirectory, "NetTweak.script" + CurrentGame.NetTweakBackupSuffix));
            state.HasKverFile = File.Exists(Path.Combine(gameDirectory, "kver.kp"));
        }

        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
        {
            using (RegistryKey sierraKey = baseKey.OpenSubKey(CurrentGame.SierraRegistryPath, false))
            {
                if (sierraKey != null)
                {
                    object sierraCdKey = sierraKey.GetValue(SierraCdKeyValueName);
                    string sierraCdKeyString = sierraCdKey as string;
                    if (!string.IsNullOrWhiteSpace(sierraCdKeyString))
                    {
                        state.HasSierraCdKey = true;
                        state.SierraCdKeyDisplay = FormatDisplayCdKey(sierraCdKeyString.Trim());
                    }

                    state.RegistryOwnedByInstaller = InstallerOwnsRegistryKeys(sierraKey);
                }
            }

            using (RegistryKey wonKeys = baseKey.OpenSubKey(WonCdKeysRegistryPath, false))
            {
                if (wonKeys != null)
                {
                    byte[] wonCdKey = wonKeys.GetValue(CurrentGame.WonRegistryValueName) as byte[];
                    state.HasWonCdKey = wonCdKey != null && wonCdKey.Length > 0;
                }
            }
        }

        if (CurrentGame.HasVirtualStore)
        {
            using (RegistryKey currentUserKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default))
            using (RegistryKey virtualStoreKey = currentUserKey.OpenSubKey(CurrentGame.SierraVirtualStoreRegistryPath, false))
            {
                if (virtualStoreKey != null)
                {
                    object virtualStoreCdKey = virtualStoreKey.GetValue(SierraCdKeyValueName);
                    string virtualStoreCdKeyString = virtualStoreCdKey as string;
                    if (!string.IsNullOrWhiteSpace(virtualStoreCdKeyString))
                    {
                        state.HasSierraCdKey = true;
                        if (string.IsNullOrWhiteSpace(state.SierraCdKeyDisplay))
                        {
                            state.SierraCdKeyDisplay = FormatDisplayCdKey(virtualStoreCdKeyString.Trim());
                        }
                    }

                    if (!state.RegistryOwnedByInstaller)
                    {
                        state.RegistryOwnedByInstaller = InstallerOwnsRegistryKeys(virtualStoreKey);
                    }
                }
            }
        }

        return state;
    }

    private static string FormatDisplayCdKey(string plainOrDisplayCdKey)
    {
        if (string.IsNullOrWhiteSpace(plainOrDisplayCdKey))
        {
            return string.Empty;
        }

        string compact = plainOrDisplayCdKey
            .Trim()
            .Replace("-", string.Empty)
            .Replace(" ", string.Empty)
            .ToUpperInvariant();

        if (compact.Length != 20)
        {
            return plainOrDisplayCdKey.Trim();
        }

        return string.Format(
            "{0}-{1}-{2}-{3}-{4}",
            compact.Substring(0, 4),
            compact.Substring(4, 4),
            compact.Substring(8, 4),
            compact.Substring(12, 4),
            compact.Substring(16, 4));
    }

    private static string BuildInstallSummaryText(ExistingInstallState existingState)
    {
        StringBuilder summary = new StringBuilder();
        summary.Append("Configures ");
        summary.Append(CurrentGame.DisplayName);
        summary.Append(" for online play: writes NetTweak.script and kver.kp to your game folder, and optionally sets up a CD key in the registry.");

        if (existingState.HasAnyRegistryCdKey)
        {
            summary.AppendLine();
            if (existingState.RegistryOwnedByInstaller)
            {
                summary.Append("An installer-managed CD key was detected and will be refreshed with a new random key by default.");
            }
            else
            {
                summary.Append("An existing CD key was detected and will be preserved unless you opt in below.");
            }
        }

        return summary.ToString();
    }

    private static string BuildRegistryHelpText(bool installRegistryKey, RegistryCdKeyOption selectedCdKey, ExistingInstallState existingState)
    {
        if (!installRegistryKey)
        {
            if (existingState.HasAnyRegistryCdKey)
            {
                if (existingState.RegistryOwnedByInstaller)
                {
                    return "Existing installer-managed " + CurrentGame.DisplayName + " registry key values were detected. Leave this off to keep the current installer key instead of refreshing it.";
                }
                return "Existing " + CurrentGame.DisplayName + " registry key values were detected. Leave this off to preserve them.";
            }

            return "Registry CD key install is turned off.";
        }

        if (existingState.HasAnyRegistryCdKey)
        {
            if (existingState.RegistryOwnedByInstaller)
            {
                return "Existing installer-managed " + CurrentGame.DisplayName + " registry key values were detected. Keeping this enabled will refresh them to " + selectedCdKey.DisplayCdKey + ".";
            }
            return "Existing " + CurrentGame.DisplayName + " registry key values were detected. Keeping this enabled will overwrite them with " + selectedCdKey.DisplayCdKey + ".";
        }

        return "Writes " + selectedCdKey.DisplayCdKey + " to the Sierra and WON registry entries for stock " + CurrentGame.DisplayName + " login.";
    }

    private static string BuildExistingRegistryPrompt(ExistingInstallState existingState, RegistryCdKeyOption selectedCdKey)
    {
        StringBuilder prompt = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(existingState.SierraCdKeyDisplay))
        {
            prompt.Append("Existing ");
            prompt.Append(CurrentGame.DisplayName);
            prompt.Append(" registry CD key detected: ");
            prompt.Append(existingState.SierraCdKeyDisplay);
            prompt.AppendLine();
            prompt.AppendLine();
        }
        else
        {
            prompt.Append("Existing ");
            prompt.Append(CurrentGame.DisplayName);
            prompt.Append(" registry CD key values were detected on this machine.");
            prompt.AppendLine();
            prompt.AppendLine();
        }

        prompt.Append("Overwrite them with ");
        prompt.Append(selectedCdKey.DisplayCdKey);
        prompt.Append("? Choose No to preserve the current registry values and continue without changing them.");
        return prompt.ToString();
    }

    private static RegistryCdKeyOption GetDefaultRegistryCdKey()
    {
        GeneratedCdKey generated = RetailCdKeyGenerator.FromDisplay(CurrentGame.RetailProductName, CurrentGame.DefaultDisplayCdKey);
        RegistryCdKeyOption option = new RegistryCdKeyOption(generated);
        if (!ByteArraysEqual(option.EncryptedCdKey, CurrentGame.DefaultEncryptedCdKey))
        {
            throw new InvalidOperationException("Embedded retail " + CurrentGame.DisplayName + " CD-key generator failed its known-good self-check.");
        }
        return option;
    }

    private static RegistryCdKeyOption PickRandomRegistryCdKey(string excludeDisplayCdKey)
    {
        return new RegistryCdKeyOption(
            RetailCdKeyGenerator.GenerateRandom(CurrentGame.RetailProductName, excludeDisplayCdKey));
    }

    private static bool ByteArraysEqual(byte[] left, byte[] right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }
        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i += 1)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }
        return true;
    }

    private static string BuildInstallSuccessMessage(InstallResult result)
    {
        StringBuilder builder = new StringBuilder();
        builder.AppendFormat("{0} is ready.", CurrentGame.DisplayName);
        builder.AppendLine();
        builder.AppendFormat("Server: {0}", result.ServerHost);
        builder.AppendLine();

        if (result.RegistryWrite != null)
        {
            builder.AppendFormat("CD key: {0}", result.RegistryWrite.DisplayCdKey);
            builder.AppendLine();
        }

        builder.AppendLine();
        builder.Append("Launch the game normally to play online.");
        return builder.ToString();
    }

    private static InstallChoices PromptForInstallChoices(string defaultValue, bool defaultWriteRegistryKeys, RegistryCdKeyOption defaultCdKey, ExistingInstallState existingState)
    {
        using (Form form = new Form())
        using (Label summaryLabel = new Label())
        using (GroupBox serverGroup = new GroupBox())
        using (Label presetLabel = new Label())
        using (ComboBox presetCombo = new ComboBox())
        using (Label customLabel = new Label())
        using (TextBox customTextBox = new TextBox())
        using (GroupBox registryGroup = new GroupBox())
        using (CheckBox registryCheckBox = new CheckBox())
        using (Label selectedKeyLabel = new Label())
        using (TextBox cdKeyTextBox = new TextBox())
        using (Button generateKeyButton = new Button())
        using (Label registryHelpLabel = new Label())
        using (Button installButton = new Button())
        using (Button cancelButton = new Button())
        {
            string initialValue = string.IsNullOrWhiteSpace(defaultValue)
                ? CurrentGame.DefaultServerHost
                : defaultValue.Trim();
            RegistryCdKeyOption selectedCdKey = defaultCdKey ?? GetDefaultRegistryCdKey();

            form.Text = CurrentGame.WindowTitle;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.ClientSize = new Size(480, 390);
            form.MinimizeBox = false;
            form.MaximizeBox = false;
            form.Font = SystemFonts.MessageBoxFont;
            form.AcceptButton = installButton;
            form.CancelButton = cancelButton;

            // --- Summary ---
            summaryLabel.Location = new Point(15, 12);
            summaryLabel.Size = new Size(450, 52);
            summaryLabel.Text = BuildInstallSummaryText(existingState);

            // --- Server group ---
            serverGroup.Text = "Server";
            serverGroup.Location = new Point(12, 68);
            serverGroup.Size = new Size(452, 108);

            presetLabel.AutoSize = true;
            presetLabel.Location = new Point(10, 22);
            presetLabel.Text = "Connect to:";

            presetCombo.DropDownStyle = ComboBoxStyle.DropDownList;
            presetCombo.Location = new Point(12, 40);
            presetCombo.Size = new Size(426, 23);
            presetCombo.TabIndex = 0;
            presetCombo.Items.Add(CurrentGame.DefaultServerHost);
            presetCombo.Items.Add(CustomHostOptionLabel);

            customLabel.AutoSize = true;
            customLabel.Location = new Point(10, 72);
            customLabel.Text = "Custom host or IP:";

            customTextBox.Location = new Point(130, 69);
            customTextBox.Size = new Size(308, 23);
            customTextBox.TabIndex = 1;

            serverGroup.Controls.Add(presetLabel);
            serverGroup.Controls.Add(presetCombo);
            serverGroup.Controls.Add(customLabel);
            serverGroup.Controls.Add(customTextBox);

            // --- Registry / CD key group ---
            registryGroup.Text = "CD Key";
            registryGroup.Location = new Point(12, 184);
            registryGroup.Size = new Size(452, 148);

            registryCheckBox.AutoSize = true;
            registryCheckBox.Location = new Point(12, 22);
            registryCheckBox.Text = "Write " + CurrentGame.DisplayName + " CD key to the registry";
            registryCheckBox.Checked = defaultWriteRegistryKeys;
            registryCheckBox.TabIndex = 2;

            selectedKeyLabel.AutoSize = true;
            selectedKeyLabel.Location = new Point(12, 52);
            selectedKeyLabel.Text = "Key:";

            cdKeyTextBox.Location = new Point(46, 49);
            cdKeyTextBox.ReadOnly = true;
            cdKeyTextBox.Size = new Size(290, 23);
            cdKeyTextBox.TabIndex = 3;
            cdKeyTextBox.Font = new Font("Consolas", 9.5f);

            generateKeyButton.Location = new Point(345, 48);
            generateKeyButton.Size = new Size(95, 25);
            generateKeyButton.Text = "Randomize";
            generateKeyButton.TabIndex = 4;

            registryHelpLabel.Location = new Point(12, 82);
            registryHelpLabel.Size = new Size(428, 56);
            registryHelpLabel.ForeColor = SystemColors.GrayText;

            registryGroup.Controls.Add(registryCheckBox);
            registryGroup.Controls.Add(selectedKeyLabel);
            registryGroup.Controls.Add(cdKeyTextBox);
            registryGroup.Controls.Add(generateKeyButton);
            registryGroup.Controls.Add(registryHelpLabel);

            // --- Buttons ---
            installButton.Text = "Install";
            installButton.Size = new Size(84, 30);
            installButton.Location = new Point(290, 346);
            installButton.TabIndex = 5;

            cancelButton.Text = "Cancel";
            cancelButton.Size = new Size(84, 30);
            cancelButton.Location = new Point(380, 346);
            cancelButton.DialogResult = DialogResult.Cancel;
            cancelButton.TabIndex = 6;

            // --- Sync state ---
            EventHandler syncSelection = delegate
            {
                bool useCustom = string.Equals(
                    presetCombo.SelectedItem as string,
                    CustomHostOptionLabel,
                    StringComparison.OrdinalIgnoreCase);
                bool installRegistryKey = registryCheckBox.Checked;
                customTextBox.Enabled = useCustom;
                customLabel.Enabled = useCustom;
                selectedKeyLabel.Enabled = installRegistryKey;
                cdKeyTextBox.Enabled = installRegistryKey;
                generateKeyButton.Enabled = installRegistryKey;
                registryHelpLabel.Enabled = installRegistryKey;
                cdKeyTextBox.Text = selectedCdKey.DisplayCdKey;
                registryHelpLabel.Text = BuildRegistryHelpText(installRegistryKey, selectedCdKey, existingState);
            };

            if (string.Equals(initialValue, CurrentGame.DefaultServerHost, StringComparison.OrdinalIgnoreCase))
            {
                presetCombo.SelectedIndex = 0;
                customTextBox.Text = string.Empty;
            }
            else
            {
                presetCombo.SelectedIndex = 1;
                customTextBox.Text = initialValue;
            }
            syncSelection(null, EventArgs.Empty);

            presetCombo.SelectedIndexChanged += syncSelection;
            registryCheckBox.CheckedChanged += syncSelection;
            generateKeyButton.Click += delegate
            {
                selectedCdKey = PickRandomRegistryCdKey(selectedCdKey.DisplayCdKey);
                syncSelection(null, EventArgs.Empty);
            };

            installButton.Click += delegate
            {
                bool useCustom = string.Equals(
                    presetCombo.SelectedItem as string,
                    CustomHostOptionLabel,
                    StringComparison.OrdinalIgnoreCase);
                if (useCustom && string.IsNullOrWhiteSpace(customTextBox.Text))
                {
                    MessageBox.Show(
                        form,
                        "Enter a custom host or IP, or switch back to the default server.",
                        CurrentGame.WindowTitle,
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    customTextBox.Focus();
                    form.DialogResult = DialogResult.None;
                    return;
                }

                try
                {
                    string candidateServerHost = useCustom
                        ? customTextBox.Text
                        : (presetCombo.SelectedItem as string ?? CurrentGame.DefaultServerHost);
                    NormalizeServerHost(candidateServerHost);
                }
                catch (InvalidOperationException ex)
                {
                    MessageBox.Show(
                        form,
                        ex.Message,
                        CurrentGame.WindowTitle,
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    if (useCustom)
                    {
                        customTextBox.Focus();
                    }
                    form.DialogResult = DialogResult.None;
                    return;
                }

                if (registryCheckBox.Checked && existingState.HasAnyRegistryCdKey && !existingState.RegistryOwnedByInstaller)
                {
                    DialogResult overwriteResult = MessageBox.Show(
                        form,
                        BuildExistingRegistryPrompt(existingState, selectedCdKey),
                        CurrentGame.WindowTitle,
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);

                    if (overwriteResult == DialogResult.No)
                    {
                        registryCheckBox.Checked = false;
                    }
                }

                form.DialogResult = DialogResult.OK;
                form.Close();
            };

            form.Controls.Add(summaryLabel);
            form.Controls.Add(serverGroup);
            form.Controls.Add(registryGroup);
            form.Controls.Add(installButton);
            form.Controls.Add(cancelButton);

            DialogResult result = form.ShowDialog();
            if (result != DialogResult.OK)
            {
                throw new OperationCanceledException();
            }

            string selectedValue = presetCombo.SelectedItem as string;
            string serverHost = string.Equals(selectedValue, CustomHostOptionLabel, StringComparison.OrdinalIgnoreCase)
                ? customTextBox.Text.Trim()
                : (string.IsNullOrWhiteSpace(selectedValue)
                    ? CurrentGame.DefaultServerHost
                    : selectedValue.Trim());

            return new InstallChoices
            {
                ServerHost = serverHost,
                WriteRegistryKeys = registryCheckBox.Checked,
                RegistryCdKey = selectedCdKey,
            };
        }
    }

    private sealed class InstallerOptions
    {
        public string ServerHost { get; private set; }
        public string GameDirectory { get; private set; }
        public string GameKey { get; private set; }
        public bool Uninstall { get; private set; }
        public bool? WriteRegistryKeys { get; private set; }

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
                if (Matches(arg, "--game", "/game"))
                {
                    options.GameKey = ReadValue(args, ref i, arg);
                    continue;
                }
                if (Matches(arg, "--skip-registry", "/skip-registry"))
                {
                    options.WriteRegistryKeys = false;
                    continue;
                }
                if (Matches(arg, "--write-registry", "/write-registry"))
                {
                    options.WriteRegistryKeys = true;
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

    private sealed class InstallChoices
    {
        public string ServerHost { get; set; }
        public bool WriteRegistryKeys { get; set; }
        public RegistryCdKeyOption RegistryCdKey { get; set; }
    }

    private sealed class RegistryCdKeyOption
    {
        public RegistryCdKeyOption(GeneratedCdKey generatedCdKey)
            : this(generatedCdKey.DisplayCdKey, generatedCdKey.PlainCdKey, generatedCdKey.EncryptedCdKey)
        {
        }

        public RegistryCdKeyOption(string displayCdKey, byte[] encryptedCdKey)
            : this(displayCdKey, displayCdKey.Replace("-", string.Empty), encryptedCdKey)
        {
        }

        private RegistryCdKeyOption(string displayCdKey, string plainCdKey, byte[] encryptedCdKey)
        {
            DisplayCdKey = displayCdKey;
            PlainCdKey = plainCdKey;
            EncryptedCdKey = encryptedCdKey;
        }

        public string DisplayCdKey { get; private set; }
        public string PlainCdKey { get; private set; }
        public byte[] EncryptedCdKey { get; private set; }
    }

    private sealed class ExistingInstallState
    {
        public bool HasSierraCdKey { get; set; }
        public bool HasWonCdKey { get; set; }
        public bool RegistryOwnedByInstaller { get; set; }
        public string SierraCdKeyDisplay { get; set; }
        public bool HasNetTweakScript { get; set; }
        public bool HasNetTweakBackup { get; set; }
        public bool HasKverFile { get; set; }

        public bool HasAnyRegistryCdKey
        {
            get { return HasSierraCdKey || HasWonCdKey; }
        }

        public bool HasBootstrapFiles
        {
            get { return HasNetTweakScript || HasKverFile; }
        }
    }

    private sealed class RegistryWriteResult
    {
        public string DisplayCdKey { get; set; }
        public string SierraRegistryValuePath { get; set; }
        public string SierraDataValuePath { get; set; }
        public string SierraVersionKeyPath { get; set; }
        public string VirtualStoreRegistryValuePath { get; set; }
        public string WonRegistryValuePath { get; set; }
    }

    private sealed class InstallResult
    {
        public string ServerHost { get; set; }
        public RegistryWriteResult RegistryWrite { get; set; }
    }
}
