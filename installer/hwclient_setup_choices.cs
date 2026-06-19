internal enum RegistryCdKeyAction
{
    KeepExisting,
    WriteGenerated,
}

internal sealed class RegistryCdKeyState
{
    public bool HasAnyRegistryCdKey { get; set; }
    public bool RegistryOwnedByInstaller { get; set; }
    public bool RegistryUsesLegacySharedDefault { get; set; }
    public string SierraCdKeyDisplay { get; set; }

    public bool ShouldRefreshByDefault
    {
        get { return RegistryOwnedByInstaller || RegistryUsesLegacySharedDefault; }
    }
}

internal static class RegistryCdKeyActionPolicy
{
    public static RegistryCdKeyAction PickDefaultAction(RegistryCdKeyState state)
    {
        if (state == null || !state.HasAnyRegistryCdKey)
        {
            return RegistryCdKeyAction.WriteGenerated;
        }
        return state.ShouldRefreshByDefault
            ? RegistryCdKeyAction.WriteGenerated
            : RegistryCdKeyAction.KeepExisting;
    }

    public static string BuildDetectedKeyText(RegistryCdKeyState state)
    {
        if (state == null || !state.HasAnyRegistryCdKey)
        {
            return "No existing registry CD key was detected.";
        }

        string keyText = string.IsNullOrWhiteSpace(state.SierraCdKeyDisplay)
            ? "Existing registry CD key values were detected."
            : "Detected registry key: " + state.SierraCdKeyDisplay;

        if (state.RegistryUsesLegacySharedDefault)
        {
            return keyText + " This looks like an older shared installer key, so replacing it is recommended.";
        }
        if (state.RegistryOwnedByInstaller)
        {
            return keyText + " This looks installer-managed, so refreshing it is recommended.";
        }
        return keyText + " This looks player-owned, so keeping it is the default.";
    }

    public static string BuildChoiceHelpText(RegistryCdKeyAction action, string generatedDisplayKey, RegistryCdKeyState state, string gameDisplayName)
    {
        if (action == RegistryCdKeyAction.KeepExisting)
        {
            return state != null && state.HasAnyRegistryCdKey
                ? "Keeps the detected registry CD key and only updates the online bootstrap files."
                : "No key was detected. Choose replacement to generate one for online login.";
        }

        return "Writes " + generatedDisplayKey + " to the Sierra and WON registry entries for stock " + gameDisplayName + " login.";
    }
}
