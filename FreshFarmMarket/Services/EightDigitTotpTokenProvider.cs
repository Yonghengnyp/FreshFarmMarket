using Microsoft.AspNetCore.Identity;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace FreshFarmMarket.Services
{
    /// <summary>
    /// Custom TOTP token provider that generates 8-digit codes instead of the default 6.
    /// </summary>
    public class EightDigitTotpSecurityStampBasedTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
        where TUser : class
    {
        private readonly ILogger<EightDigitTotpSecurityStampBasedTokenProvider<TUser>> _logger;

        public EightDigitTotpSecurityStampBasedTokenProvider(
            ILogger<EightDigitTotpSecurityStampBasedTokenProvider<TUser>> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Generates an 8-digit TOTP code for the user.
        /// </summary>
        public async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            var token = await manager.CreateSecurityTokenAsync(user);
            var modifier = await GetModifierAsync(purpose, manager, user);
            var code = Rfc6238AuthenticationService.GenerateCode(token, modifier, 8); // 8 digits
            
            _logger.LogInformation($"Generated 8-digit TOTP code for user");
            return code.ToString(new string('0', 8), CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Validates an 8-digit TOTP code for the user.
        /// </summary>
        public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Token validation failed: token is null or empty");
                return false;
            }

            // Strip spaces and validate format
            token = token.Replace(" ", string.Empty).Replace("-", string.Empty);
            
            if (token.Length != 8 || !int.TryParse(token, out int code))
            {
                _logger.LogWarning($"Token validation failed: invalid format (expected 8 digits, got {token.Length} characters)");
                return false;
            }

            var securityToken = await manager.CreateSecurityTokenAsync(user);
            var modifier = await GetModifierAsync(purpose, manager, user);

            // Check current code and adjacent time windows (±1 period = 90 seconds total)
            for (int i = -1; i <= 1; i++)
            {
                var expectedCode = Rfc6238AuthenticationService.GenerateCode(securityToken, modifier, i, 8);
                if (expectedCode == code)
                {
                    _logger.LogInformation($"Token validated successfully (offset: {i})");
                    return true;
                }
            }

            _logger.LogWarning("Token validation failed: code does not match");
            return false;
        }

        /// <summary>
        /// Always returns true - this provider can generate tokens for any user.
        /// </summary>
        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            return Task.FromResult(true);
        }

        /// <summary>
        /// Gets the modifier for TOTP generation (includes purpose and user security stamp).
        /// </summary>
        private async Task<string> GetModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            var userId = await manager.GetUserIdAsync(user);
            return $"Totp:{purpose}:{userId}";
        }
    }

    /// <summary>
    /// RFC 6238 TOTP implementation with support for 8-digit codes.
    /// Based on the standard TOTP algorithm.
    /// </summary>
    public static class Rfc6238AuthenticationService
    {
        private const int TimeStepSeconds = 30; // Standard TOTP time step

        /// <summary>
        /// Generates a TOTP code with the specified number of digits.
        /// </summary>
        public static int GenerateCode(byte[] securityToken, string modifier, int digits = 6)
        {
            return GenerateCode(securityToken, modifier, 0, digits);
        }

        /// <summary>
        /// Generates a TOTP code with time offset.
        /// </summary>
        public static int GenerateCode(byte[] securityToken, string modifier, int offset, int digits = 6)
        {
            var timestep = GetCurrentTimeStepNumber() + offset;
            var hash = ComputeTotp(securityToken, modifier, timestep);
            var code = ComputeCode(hash, digits);
            return code;
        }

        private static long GetCurrentTimeStepNumber()
        {
            var delta = DateTimeOffset.UtcNow - DateTimeOffset.UnixEpoch;
            return (long)(delta.TotalSeconds / TimeStepSeconds);
        }

        private static byte[] ComputeTotp(byte[] securityToken, string modifier, long timestep)
        {
            // Combine security token with modifier
            var modifierBytes = Encoding.UTF8.GetBytes(modifier);
            var combined = new byte[securityToken.Length + modifierBytes.Length];
            Buffer.BlockCopy(securityToken, 0, combined, 0, securityToken.Length);
            Buffer.BlockCopy(modifierBytes, 0, combined, securityToken.Length, modifierBytes.Length);

            // Create HMAC key
            using var hmac = new HMACSHA1(combined);
            
            // Convert timestep to bytes (big-endian)
            var timestepBytes = BitConverter.GetBytes(timestep);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(timestepBytes);
            }

            // Compute HMAC
            return hmac.ComputeHash(timestepBytes);
        }

        private static int ComputeCode(byte[] hash, int digits)
        {
            // Dynamic truncation (RFC 6238 Section 5.3)
            var offset = hash[hash.Length - 1] & 0x0F;
            
            var binaryCode = ((hash[offset] & 0x7F) << 24)
                           | ((hash[offset + 1] & 0xFF) << 16)
                           | ((hash[offset + 2] & 0xFF) << 8)
                           | (hash[offset + 3] & 0xFF);

            // Get the specified number of digits
            var modulus = (int)Math.Pow(10, digits);
            return binaryCode % modulus;
        }
    }
}
