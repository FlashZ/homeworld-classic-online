using System;
using System.IO;

internal static class MapPackInstallerTests
{
    private static int failures;

    private static void Main()
    {
        CopiesOnlyMatchingGameMaps();
        SkipsExistingMapFolders();
        ReportsMissingSourceDirectory();
        CdKeyChoiceDefaultsPreferKeepingPlayerOwnedKeys();
        CdKeyChoiceDefaultsReplaceInstallerOwnedKeys();

        if (failures > 0)
        {
            Environment.Exit(1);
        }
    }

    private static void CopiesOnlyMatchingGameMaps()
    {
        string root = CreateTempRoot();
        string archive = Path.Combine(root, "archive");
        string game = Path.Combine(root, "Homeworld");
        Directory.CreateDirectory(Path.Combine(archive, "repo-main", "HW1_maps", "Battlefield2"));
        Directory.CreateDirectory(Path.Combine(archive, "repo-main", "CATA_maps", "CataOnly2"));
        File.WriteAllText(Path.Combine(archive, "repo-main", "HW1_maps", "Battlefield2", "Battlefield.level"), "level");
        Directory.CreateDirectory(game);

        MapPackInstallResult result = MapPackInstaller.CopyMapsFromExtractedArchive(
            archive,
            "HW1_maps",
            game,
            null);

        AssertTrue(File.Exists(Path.Combine(game, "MultiPlayer", "Battlefield2", "Battlefield.level")), "copies Homeworld map");
        AssertTrue(!Directory.Exists(Path.Combine(game, "MultiPlayer", "CataOnly2")), "does not copy Cataclysm maps");
        AssertEqual(1, result.CopiedCount, "copied count");
        AssertEqual(0, result.SkippedCount, "skipped count");
    }

    private static void SkipsExistingMapFolders()
    {
        string root = CreateTempRoot();
        string archive = Path.Combine(root, "archive");
        string game = Path.Combine(root, "Homeworld");
        Directory.CreateDirectory(Path.Combine(archive, "repo-main", "HW1_maps", "Garden2"));
        File.WriteAllText(Path.Combine(archive, "repo-main", "HW1_maps", "Garden2", "Garden.level"), "new");
        Directory.CreateDirectory(Path.Combine(game, "MultiPlayer", "Garden2"));
        File.WriteAllText(Path.Combine(game, "MultiPlayer", "Garden2", "Garden.level"), "existing");

        MapPackInstallResult result = MapPackInstaller.CopyMapsFromExtractedArchive(
            archive,
            "HW1_maps",
            game,
            null);

        AssertEqual("existing", File.ReadAllText(Path.Combine(game, "MultiPlayer", "Garden2", "Garden.level")), "existing file remains");
        AssertEqual(0, result.CopiedCount, "copied count");
        AssertEqual(1, result.SkippedCount, "skipped count");
    }

    private static void ReportsMissingSourceDirectory()
    {
        string root = CreateTempRoot();
        Directory.CreateDirectory(Path.Combine(root, "archive"));
        Directory.CreateDirectory(Path.Combine(root, "game"));

        try
        {
            MapPackInstaller.CopyMapsFromExtractedArchive(
                Path.Combine(root, "archive"),
                "HW1_maps",
                Path.Combine(root, "game"),
                null);
            Fail("missing source directory should throw");
        }
        catch (InvalidOperationException ex)
        {
            AssertTrue(ex.Message.Contains("HW1_maps"), "mentions missing source directory");
        }
    }

    private static void CdKeyChoiceDefaultsPreferKeepingPlayerOwnedKeys()
    {
        RegistryCdKeyState state = new RegistryCdKeyState
        {
            HasAnyRegistryCdKey = true,
            SierraCdKeyDisplay = "KAY9-2MJT-8P3D-R4FW-7192",
            RegistryOwnedByInstaller = false,
            RegistryUsesLegacySharedDefault = false,
        };

        RegistryCdKeyAction action = RegistryCdKeyActionPolicy.PickDefaultAction(state);

        AssertEqual(RegistryCdKeyAction.KeepExisting, action, "player-owned default action");
    }

    private static void CdKeyChoiceDefaultsReplaceInstallerOwnedKeys()
    {
        RegistryCdKeyState state = new RegistryCdKeyState
        {
            HasAnyRegistryCdKey = true,
            SierraCdKeyDisplay = "NYX7-ZEC9-FYZ6-GUX8-4253",
            RegistryOwnedByInstaller = true,
            RegistryUsesLegacySharedDefault = false,
        };

        RegistryCdKeyAction action = RegistryCdKeyActionPolicy.PickDefaultAction(state);

        AssertEqual(RegistryCdKeyAction.WriteGenerated, action, "installer-owned default action");
    }

    private static string CreateTempRoot()
    {
        string path = Path.Combine(Path.GetTempPath(), "won-map-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void AssertEqual<T>(T expected, T actual, string label)
    {
        if (!object.Equals(expected, actual))
        {
            Fail(label + ": expected " + expected + ", got " + actual);
        }
    }

    private static void AssertTrue(bool condition, string label)
    {
        if (!condition)
        {
            Fail(label);
        }
    }

    private static void Fail(string message)
    {
        failures += 1;
        Console.Error.WriteLine("FAIL: " + message);
    }
}
