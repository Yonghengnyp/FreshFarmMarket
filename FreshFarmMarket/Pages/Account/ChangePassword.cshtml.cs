using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages.Account
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly SignInManager<Member> _signInManager;
        private readonly PasswordValidationService _passwordValidation;
        private readonly AuditLogService _auditLogService;
        private readonly ILogger<ChangePasswordModel> _logger;

        public ChangePasswordModel(
            UserManager<Member> userManager,
            SignInManager<Member> signInManager,
            PasswordValidationService passwordValidation,
            AuditLogService auditLogService,
            ILogger<ChangePasswordModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordValidation = passwordValidation;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public int DaysUntilExpiry { get; set; }
        public bool PasswordExpiringSoon { get; set; }
        public bool PasswordExpired { get; set; }
        public int MinutesUntilCanChange { get; set; }
        public bool CanChangeNow { get; set; } = true;

        public class InputModel
        {
            [Required(ErrorMessage = "Current password is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "New password is required")]
            [StringLength(100, ErrorMessage = "Password must be at least {2} characters long", MinimumLength = 12)]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string NewPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password confirmation is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // Check password age (handle nullable DateTime)
            var lastPasswordChange = user.LastPasswordChangeDate ?? DateTime.UtcNow;
            DaysUntilExpiry = _passwordValidation.GetDaysUntilPasswordExpires(lastPasswordChange);
            PasswordExpiringSoon = _passwordValidation.IsPasswordExpiringSoon(lastPasswordChange);
            PasswordExpired = _passwordValidation.MustChangePassword(lastPasswordChange);

            // Check minimum age restriction
            CanChangeNow = _passwordValidation.CanChangePassword(lastPasswordChange);
            MinutesUntilCanChange = _passwordValidation.GetMinutesUntilCanChange(lastPasswordChange);

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Initialize CanChangeNow to true by default
            CanChangeNow = true;
            
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // 1. CHECK MINIMUM PASSWORD AGE
            var lastPasswordChange = user.LastPasswordChangeDate ?? DateTime.UtcNow;
            if (!_passwordValidation.CanChangePassword(lastPasswordChange))
            {
                var minutesRemaining = _passwordValidation.GetMinutesUntilCanChange(lastPasswordChange);
                var policyInfo = _passwordValidation.GetPasswordPolicy();
                
                ModelState.AddModelError(string.Empty, 
                    $"Password cannot be changed yet. You must wait {policyInfo.MinPasswordAgeMinutes} minutes after the last password change. " +
                    $"Time remaining: {minutesRemaining} minute(s).");
                
                await _auditLogService.LogActionAsync(user.Id, "Password Change Failed", 
                    "Minimum password age not met", false, $"Minutes remaining: {minutesRemaining}");
                
                CanChangeNow = false;
                MinutesUntilCanChange = minutesRemaining;
                return Page();
            }

            // 2. VALIDATE PASSWORD COMPLEXITY
            var validationResult = _passwordValidation.ValidatePassword(Input.NewPassword);
            if (!validationResult.IsValid)
            {
                foreach (var error in validationResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error);
                }
                
                await _auditLogService.LogActionAsync(user.Id, "Password Change Failed", 
                    "Password complexity requirements not met", false);
                return Page();
            }

            // 3. CHECK PASSWORD HISTORY (prevent reuse)
            var isInHistory = await _passwordValidation.IsPasswordInHistoryAsync(user.Id, Input.NewPassword, user);
            if (isInHistory)
            {
                var policyInfo = _passwordValidation.GetPasswordPolicy();
                ModelState.AddModelError(string.Empty, 
                    $"Cannot reuse any of your last {policyInfo.PasswordHistoryCount} passwords. Please choose a different password.");
                
                await _auditLogService.LogActionAsync(user.Id, "Password Change Failed", 
                    "Password found in history - reuse attempted", false);
                return Page();
            }

            // 4. VERIFY CURRENT PASSWORD AND CHANGE
            var changePasswordResult = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                
                await _auditLogService.LogActionAsync(user.Id, "Password Change Failed", 
                    "Current password incorrect", false);
                return Page();
            }

            // 5. UPDATE LAST PASSWORD CHANGE DATE
            user.LastPasswordChangeDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // 6. SAVE NEW PASSWORD TO HISTORY
            var newPasswordHash = user.PasswordHash!;
            await _passwordValidation.SavePasswordToHistoryAsync(user.Id, newPasswordHash);

            // 7. REFRESH SIGN-IN (important for security)
            await _signInManager.RefreshSignInAsync(user);

            // 8. LOG SUCCESS
            await _auditLogService.LogActionAsync(user.Id, "Password Changed", 
                "Password changed successfully", true);

            _logger.LogInformation($"? User {user.Email} changed their password successfully");

            StatusMessage = "? Your password has been changed successfully!";
            return RedirectToPage();
        }
    }
}
