using System.Text.RegularExpressions;

namespace FreshFarmMarket.Services
{
    /// <summary>
    /// Service for validating password strength and complexity
    /// Requirements: Min 12 chars, upper, lower, numbers, special chars
    /// </summary>
    public class PasswordValidationService
    {
        private readonly int _minLength;
        private readonly int _maxPasswordAge; // in days
        private readonly int _minPasswordAge; // in minutes
        private readonly int _passwordHistoryCount;

        public PasswordValidationService(IConfiguration configuration)
        {
            _minLength = configuration.GetValue<int>("PasswordPolicy:MinLength", 12);
            _maxPasswordAge = configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
            _minPasswordAge = configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeMinutes", 5);
            _passwordHistoryCount = configuration.GetValue<int>("PasswordPolicy:PasswordHistoryCount", 2);
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
        /// Checks if password meets minimum age requirement
        /// </summary>
        public bool CanChangePassword(DateTime lastPasswordChangeDate)
        {
            var minutesSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalMinutes;
            return minutesSinceLastChange >= _minPasswordAge;
        }

        /// <summary>
        /// Checks if password has exceeded maximum age
        /// </summary>
        public bool MustChangePassword(DateTime lastPasswordChangeDate)
        {
            var daysSinceLastChange = (DateTime.UtcNow - lastPasswordChangeDate).TotalDays;
            return daysSinceLastChange >= _maxPasswordAge;
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
    }

    public class PasswordValidationResult
    {
        public bool IsValid { get; set; } = true;
        public List<string> Errors { get; set; } = new List<string>();
        public int StrengthScore { get; set; }
        public string StrengthLevel { get; set; } = string.Empty;
    }
}
