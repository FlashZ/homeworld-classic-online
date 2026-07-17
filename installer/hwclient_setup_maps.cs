using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;

internal sealed class MapPackProgress
{
    public string Stage { get; set; }
    public int Percent { get; set; }
    public long BytesReceived { get; set; }
    public long TotalBytes { get; set; }
    public string Detail { get; set; }
}

internal sealed class MapPackInstallResult
{
    public bool Attempted { get; set; }
    public bool Succeeded { get; set; }
    public string ErrorMessage { get; set; }
    public int CopiedCount { get; set; }
    public int SkippedCount { get; set; }
    public string DestinationDirectory { get; set; }

    public string BuildSummaryLine()
    {
        if (!Attempted)
        {
            return "Community maps: not selected.";
        }

        if (!Succeeded)
        {
            string error = string.IsNullOrWhiteSpace(ErrorMessage)
                ? "unknown error"
                : ErrorMessage;
            return "Community maps: failed - " + error + ".";
        }

        string summary = "Community maps: copied " + CopiedCount + ", skipped " + SkippedCount + " existing";
        if (!string.IsNullOrWhiteSpace(DestinationDirectory))
        {
            summary += " in " + DestinationDirectory;
        }
        return summary + ".";
    }
}

internal static class MapPackInstaller
{
    // Keep installer releases reproducible: this is a reviewed map-pack commit,
    // not the moving contents of the repository's main branch.
    public const string RepositoryArchiveUrl = "https://github.com/FlashZ/Homeworld_Map_Collection/archive/df266b9ca8caab4c1fe3c7e27fe93bce4dcf1210.zip";
    public const string RepositoryArchiveSha256 = "b61a92cd468fdfb7e32a4e0cc365d3e12d79dd46a6779d38d6168a8cb52ba069";
    public const string HomeworldSourceDirectoryName = "HW1_maps";
    public const string CataclysmSourceDirectoryName = "CATA_maps";
    private const SecurityProtocolType Tls12 = (SecurityProtocolType)3072;

    public static MapPackInstallResult CopyMapsFromExtractedArchive(
        string extractedArchiveDirectory,
        string sourceDirectoryName,
        string gameDirectory,
        Action<MapPackProgress> progress)
    {
        if (string.IsNullOrWhiteSpace(extractedArchiveDirectory))
        {
            throw new ArgumentException("Extracted archive directory is required.", "extractedArchiveDirectory");
        }
        if (string.IsNullOrWhiteSpace(sourceDirectoryName))
        {
            throw new ArgumentException("Map source directory name is required.", "sourceDirectoryName");
        }
        if (string.IsNullOrWhiteSpace(gameDirectory))
        {
            throw new ArgumentException("Game directory is required.", "gameDirectory");
        }

        string sourceDirectory = FindDirectory(extractedArchiveDirectory, sourceDirectoryName);
        if (sourceDirectory == null)
        {
            throw new InvalidOperationException("The downloaded map archive did not contain " + sourceDirectoryName + ".");
        }

        string destinationRoot = Path.Combine(gameDirectory, "MultiPlayer");
        Directory.CreateDirectory(destinationRoot);

        string[] mapDirectories = Directory.GetDirectories(sourceDirectory);
        int copied = 0;
        int skipped = 0;
        for (int i = 0; i < mapDirectories.Length; i += 1)
        {
            string mapDirectory = mapDirectories[i];
            string destination = Path.Combine(destinationRoot, Path.GetFileName(mapDirectory));
            if (progress != null)
            {
                progress(new MapPackProgress
                {
                    Stage = "Copying maps",
                    Percent = mapDirectories.Length == 0 ? 100 : (int)((i * 100L) / mapDirectories.Length),
                    Detail = Path.GetFileName(mapDirectory),
                });
            }

            if (Directory.Exists(destination))
            {
                skipped += 1;
                continue;
            }

            CopyDirectory(mapDirectory, destination);
            copied += 1;
        }

        if (progress != null)
        {
            progress(new MapPackProgress
            {
                Stage = "Copying maps",
                Percent = 100,
                Detail = "Copied " + copied + " maps, skipped " + skipped + " existing.",
            });
        }

        return new MapPackInstallResult
        {
            Attempted = true,
            Succeeded = true,
            CopiedCount = copied,
            SkippedCount = skipped,
            DestinationDirectory = destinationRoot,
        };
    }

    public static void DownloadArchive(string url, string destinationPath, string expectedSha256, Action<MapPackProgress> progress)
    {
        try
        {
            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | Tls12;
        }
        catch (NotSupportedException)
        {
        }

        using (WebClient client = new WebClient())
        {
            client.DownloadProgressChanged += delegate(object sender, DownloadProgressChangedEventArgs e)
            {
                if (progress != null)
                {
                    progress(new MapPackProgress
                    {
                        Stage = "Downloading community maps",
                        Percent = e.ProgressPercentage,
                        BytesReceived = e.BytesReceived,
                        TotalBytes = e.TotalBytesToReceive,
                        Detail = FormatBytes(e.BytesReceived) + " of " + FormatBytes(e.TotalBytesToReceive),
                    });
                }
            };
            client.DownloadFile(new Uri(url), destinationPath);
        }

        VerifyArchiveSha256(destinationPath, expectedSha256);
    }

    private static void VerifyArchiveSha256(string archivePath, string expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(expectedSha256))
        {
            throw new ArgumentException("Expected map archive SHA-256 is required.", "expectedSha256");
        }

        string actualSha256;
        using (SHA256 sha256 = SHA256.Create())
        using (FileStream archive = File.OpenRead(archivePath))
        {
            actualSha256 = BitConverter.ToString(sha256.ComputeHash(archive))
                .Replace("-", string.Empty)
                .ToLowerInvariant();
        }

        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Downloaded map archive failed SHA-256 verification. Expected "
                + expectedSha256 + ", got " + actualSha256 + ".");
        }
    }

    private static string FindDirectory(string root, string directoryName)
    {
        foreach (string candidate in Directory.GetDirectories(root, directoryName, SearchOption.AllDirectories))
        {
            if (string.Equals(Path.GetFileName(candidate), directoryName, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }
        return null;
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string directory in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
        {
            string relative = directory.Substring(source.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            Directory.CreateDirectory(Path.Combine(destination, relative));
        }
        foreach (string file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            string relative = file.Substring(source.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            File.Copy(file, Path.Combine(destination, relative), false);
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "unknown size";
        }
        if (bytes >= 1024 * 1024)
        {
            return (bytes / 1024d / 1024d).ToString("0.0") + " MB";
        }
        return (bytes / 1024d).ToString("0.0") + " KB";
    }
}
