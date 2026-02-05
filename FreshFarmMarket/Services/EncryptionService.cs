using System.Security.Cryptography;
using System.Text;

namespace FreshFarmMarket.Services
{
    /// <summary>
    /// Service for encrypting and decrypting sensitive data like credit card numbers
    /// Uses AES-256 encryption
    /// </summary>
    public class EncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public EncryptionService(IConfiguration configuration)
        {
            // Get encryption key from configuration
            // In production, store this in Azure Key Vault or similar secure storage
            var keyString = configuration["Encryption:Key"] ?? throw new InvalidOperationException("Encryption key not configured");
            var ivString = configuration["Encryption:IV"] ?? throw new InvalidOperationException("Encryption IV not configured");

            _key = Convert.FromBase64String(keyString);
            _iv = Convert.FromBase64String(ivString);

            // Validate key and IV lengths
            if (_key.Length != 32) // 256 bits
                throw new InvalidOperationException("Encryption key must be 32 bytes (256 bits)");
            if (_iv.Length != 16) // 128 bits
                throw new InvalidOperationException("Encryption IV must be 16 bytes (128 bits)");
        }

        /// <summary>
        /// Encrypts plaintext data
        /// </summary>
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var msEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            return Convert.ToBase64String(msEncrypt.ToArray());
        }

        /// <summary>
        /// Decrypts encrypted data
        /// </summary>
        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText));
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            return srDecrypt.ReadToEnd();
        }

        /// <summary>
        /// Masks credit card number for display (shows only last 4 digits)
        /// </summary>
        public string MaskCreditCard(string creditCardNumber)
        {
            if (string.IsNullOrEmpty(creditCardNumber) || creditCardNumber.Length < 4)
                return "****";

            return "**** **** **** " + creditCardNumber.Substring(creditCardNumber.Length - 4);
        }

        /// <summary>
        /// Generates a random encryption key (for initial setup)
        /// </summary>
        public static string GenerateKey()
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            return Convert.ToBase64String(aes.Key);
        }

        /// <summary>
        /// Generates a random IV (for initial setup)
        /// </summary>
        public static string GenerateIV()
        {
            using var aes = Aes.Create();
            aes.GenerateIV();
            return Convert.ToBase64String(aes.IV);
        }
    }
}
