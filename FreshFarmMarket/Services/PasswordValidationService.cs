using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using FreshFarmMarket.Models;
using WebApp_Core_Identity.Model;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket.Services
{
    /// <summary>
    /// Service for validating password strength, complexity, history, and age
    /// Requirements: Min 12 chars, upper, lower, numbers, special chars, history check, age restrictions
    /// </summary>
    public class PasswordValidationService
    {
        private readonly int _minLength;
        private readonly int _maxPasswordAge; // in days
        private readonly int _minPasswordAge; // in minutes
        private readonly int _passwordHistoryCount;
        private readonly AuthDbContext _context;
        private readonly IPasswordHasher<Member> _passwordHasher;
        private readonly ILogger<PasswordValidationService> _logger;

        public PasswordValidationService(
            IConfiguration configuration,
            AuthDbContext context,
            IPasswordHasher<Member> passwordHasher,
            ILogger<PasswordValidationService> logger)
        {
            _minLength = configuration.GetValue<int>("PasswordPolicy:MinLength", 12);
            _maxPasswordAge = configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
            _minPasswordAge = configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeMinutes", 5);
            _passwordHistoryCount = configuration.GetValue<int>("PasswordPolicy:PasswordHistoryCount", 2);
            _context = context;
            _passwordHasher = passwordHasher;
            _logger = logger;
        }

        /// <summary>
        /// Validates password complexity and returns validation result
        /// </summary>
        public PasswordValidationResult ValidatePassword(string password)
        {
            var result = new PasswordValidationResult();

            if (string.IsNullOrEmpty(password))
            {
                result.IsValid = false;
                result.Errors.Add("Password is required");
                return result;
            }

            // Check minimum length
            if (password.Length < _minLength)
            {
                result.IsValid = false;
                result.Errors.Add($"Password must be at least {_minLength} characters long");
            }

            // Check for uppercase letter
            if (!Regex.IsMatch(password, @"[A-Z]"))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one uppercase letter");
            }

            // Check for lowercase letter
            if (!Regex.IsMatch(password, @"[a-z]"))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one lowercase letter");
            }

            // Check for digit
            if (!Regex.IsMatch(password, @"[0-9]"))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one number");
            }

            // Check for special character
            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]"))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one special character");
            }

            // Calculate strength score
            result.StrengthScore = CalculateStrengthScore(password);
            result.StrengthLevel = GetStrengthLevel(result.StrengthScore);

            return result;
        }

        /// <summary>
        /// Validates password against history (prevents reuse of last N passwords)
        /// </summary>
        public async Task<bool> IsPasswordInHistoryAsync(int memberId, string newPassword, Member member)
        {
            try
            {
                // Get last N password hashes from history
                var passwordHistory = await _context.PasswordHistories
                    .Where(ph => ph.MemberId == memberId)
                    .OrderByDescending(ph => ph.ChangedDate)
                    .Take(_passwordHistoryCount)
                    .Select(ph => ph.PasswordHash)
                    .ToListAsync();

                // Check if new password matches any in history
                foreach (var oldHash in passwordHistory)
                {
                    var verificationResult = _passwordHasher.VerifyHashedPassword(member, oldHash, newPassword);
                    if (verificationResult == PasswordVerificationResult.Success || 
                        verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
                    {
                        _logger.LogWarning($"User {memberId} attempted to reuse a recent password");
                        return true; // Password found in history
                    }
                }

                return false; // Password not in history
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking password history for user {memberId}");
                return false; // Allow password change if check fails
            }
        }

        /// <summary>
        /// Saves password to history
        /// </summary>
        public async Task SavePasswordToHistoryAsync(int memberId, string passwordHash)
        {
            try
            {
                // Add new password to history
                var historyEntry = new PasswordHistory
                {
                    MemberId = memberId,
                    PasswordHash = passwordHash,
                    ChangedDate = DateTime.UtcNow
                };

                _context.PasswordHistories.Add(historyEntry);

                // Delete old password history entries (keep only the last N)
                var oldEntries = await _context.PasswordHistories
                    .Where(ph => ph.MemberId == memberId)
                    .OrderByDescending(ph => ph.ChangedDate)
                    .Skip(_passwordHistoryCount)
                    .ToListAsync();

                if (oldEntries.Any())
                {
                    _context.PasswordHistories.RemoveRange(oldEntries);
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation($"Password saved to history for user {memberId}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving password to history for user {memberId}");
                // Don't throw - password change should still succeed
            }
        }

        /// <summary>
        /// Calculates password strength score (0-100)
        /// </summary>
        private int CalculateStrengthScore(string password)
        {
            int score = 0;

            // Length bonus
            score += Math.Min(password.Length * 2, 30);

            // Character variety bonuses
            if (Regex.IsMatch(password, @"[A-Z]")) score += 10;
            if (Regex.IsMatch(password, @"[a-z]")) score += 10;
            if (Regex.IsMatch(password, @"[0-9]")) score += 10;
            if (Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]")) score += 15;

            // Multiple occurrences bonus
            if (Regex.Matches(password, @"[A-Z]").Count >= 2) score += 5;
            if (Regex.Matches(password, @"[a-z]").Count >= 2) score += 5;
            if (Regex.Matches(password, @"[0-9]").Count >= 2) score += 5;
            if (Regex.Matches(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]").Count >= 2) score += 10;

            return Math.Min(score, 100);
        }

        /// <summary>
        /// Gets strength level based on score
        /// </summary>
        private string GetStrengthLevel(int score)
        {
            if (score >= 80) return "STRONG";
            if (score >= 60) return "GOOD";
            if (score >= 40) return "FAIR";
            return "WEAK";
        }

        /// <summary>
        /// Checks if password meets minimum age requirement (cannot change too soon)
        /// </summary>
        public bool CanChangePassword(DateTime lastPasswordChangeDate)
        {
            var minutesSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalMinutes;
            var canChange = minutesSinceLastChange >= _minPasswordAge;
            
            if (!canChange)
            {
                _logger.LogWarning($"Password change attempt blocked - minimum age not met. Minutes since last change: {minutesSinceLastChange}");
            }
            
            return canChange;
        }

        /// <summary>
        /// Gets minutes remaining until password can be changed
        /// </summary>
        public int GetMinutesUntilCanChange(DateTime lastPasswordChangeDate)
        {
            var minutesSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalMinutes;
            var minutesRemaining = _minPasswordAge - (int)minutesSinceLastChange;
            return Math.Max(0, minutesRemaining);
        }

        /// <summary>
        /// Checks if password has exceeded maximum age (must change)
        /// </summary>
        public bool MustChangePassword(DateTime lastPasswordChangeDate)
        {
            var daysSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalDays;
            var mustChange = daysSinceLastChange >= _maxPasswordAge;
            
            if (mustChange)
            {
                _logger.LogWarning($"Password has expired - days since last change: {daysSinceLastChange}");
            }
            
            return mustChange;
        }

        /// <summary>
        /// Gets days until password expires
        /// </summary>
        public int GetDaysUntilPasswordExpires(DateTime lastPasswordChangeDate)
        {
            var daysSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalDays;
            var daysRemaining = _maxPasswordAge - (int)daysSinceLastChange;
            return Math.Max(0, daysRemaining);
        }

        /// <summary>
        /// Checks if password is about to expire (within warning threshold)
        /// </summary>
        public bool IsPasswordExpiringSoon(DateTime lastPasswordChangeDate, int warningDaysThreshold = 7)
        {
            var daysRemaining = GetDaysUntilPasswordExpires(lastPasswordChangeDate);
            return daysRemaining > 0 && daysRemaining <= warningDaysThreshold;
        }

        /// <summary>
        /// Gets password policy information
        /// </summary>
        public PasswordPolicyInfo GetPasswordPolicy()
        {
            return new PasswordPolicyInfo
            {
                MinLength = _minLength,
                MaxPasswordAgeDays = _maxPasswordAge,
                MinPasswordAgeMinutes = _minPasswordAge,
                PasswordHistoryCount = _passwordHistoryCount
            };
        }
    }

    public class PasswordValidationResult
    {
        public bool IsValid { get; set; } = true;
        public List<string> Errors { get; set; } = new List<string>();
        public int StrengthScore { get; set; }
        public string StrengthLevel { get; set; } = string.Empty;
    }

    public class PasswordPolicyInfo
    {
        public int MinLength { get; set; }
        public int MaxPasswordAgeDays { get; set; }
        public int MinPasswordAgeMinutes { get; set; }
        public int PasswordHistoryCount { get; set; }
    }
}
