using FreshFarmMarket.Services;

namespace FreshFarmMarket.Helpers
{
    /// <summary>
    /// Helper class to generate encryption keys for initial setup
    /// Run this once to generate keys, then add them to appsettings.json
    /// </summary>
    public static class EncryptionKeyGenerator
    {
        public static void GenerateAndPrintKeys()
        {
            var key = EncryptionService.GenerateKey();
            var iv = EncryptionService.GenerateIV();

            Console.WriteLine("=== Encryption Keys Generated ===");
            Console.WriteLine($"Key: {key}");
            Console.WriteLine($"IV: {iv}");
            Console.WriteLine("Add these to appsettings.json under 'Encryption' section");
            Console.WriteLine("IMPORTANT: Keep these keys secure and never commit them to source control!");
        }
    }
}
