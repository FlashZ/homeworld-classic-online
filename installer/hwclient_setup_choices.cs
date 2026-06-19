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
}
