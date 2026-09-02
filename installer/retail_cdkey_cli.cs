using System;

internal static class RetailCdKeyCli
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2 || !string.Equals(args[0], "--product", StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("Usage: RetailCdKeyGen.exe --product Homeworld|Cataclysm");
                return 2;
            }

            string product = args[1];
            if (!string.Equals(product, "Homeworld", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(product, "Cataclysm", StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("Product must be Homeworld or Cataclysm.");
                return 2;
            }

            product = string.Equals(product, "Homeworld", StringComparison.OrdinalIgnoreCase)
                ? "Homeworld"
                : "Cataclysm";
            GeneratedCdKey generated = RetailCdKeyGenerator.GenerateRandom(product, string.Empty);
            string encryptedHex = BitConverter.ToString(generated.EncryptedCdKey).Replace("-", string.Empty);
            Console.WriteLine(
                "[{\"display_key\":\"" + generated.DisplayCdKey
                + "\",\"plain_key\":\"" + generated.PlainCdKey
                + "\",\"encrypted_key_hex\":\"" + encryptedHex
                + "\",\"beta\":false}]"
            );
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ERROR: " + ex.Message);
            return 1;
        }
    }
}
