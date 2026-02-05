using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly PasswordValidationService _passwordValidation;
        private readonly AuditLogService _auditLogService;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(
            UserManager<Member> userManager,
            PasswordValidationService passwordValidation,
            AuditLogService auditLogService,
            ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _passwordValidation = passwordValidation;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "New password is required")]
            [StringLength(100, ErrorMessage = "Password must be at least {2} characters long", MinimumLength = 12)]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string Password { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password confirmation is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm Password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; } = string.Empty;

            [Required]
            public string Code { get; set; } = string.Empty;
        }

        public IActionResult OnGet(string? code = null, string? email = null)
        {
            if (code == null || email == null)
            {
                return BadRequest("A code and email must be supplied for password reset.");
            }
            else
            {
                Input = new InputModel
                {
                    Code = code,
                    Email = email
                };
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                _logger.LogWarning($"Password reset attempted for non-existent email: {Input.Email}");
                await _auditLogService.LogActionAsync(null, "Password Reset Failed", 
                    $"Non-existent email: {Input.Email}", false, "User not found");
                
                StatusMessage = "? If an account with that email exists, a password reset has been completed.";
                return RedirectToPage("/Account/Login");
            }

            // 1. VALIDATE PASSWORD COMPLEXITY
            var validationResult = _passwordValidation.ValidatePassword(Input.Password);
            if (!validationResult.IsValid)
            {
                foreach (var error in validationResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error);
                }
                
                await _auditLogService.LogActionAsync(user.Id, "Password Reset Failed", 
                    "Password complexity requirements not met", false);
                return Page();
            }

            // 2. CHECK PASSWORD HISTORY (prevent reuse)
            var isInHistory = await _passwordValidation.IsPasswordInHistoryAsync(user.Id, Input.Password, user);
            if (isInHistory)
            {
                var policyInfo = _passwordValidation.GetPasswordPolicy();
                ModelState.AddModelError(string.Empty, 
                    $"Cannot reuse any of your last {policyInfo.PasswordHistoryCount} passwords. Please choose a different password.");
                
                await _auditLogService.LogActionAsync(user.Id, "Password Reset Failed", 
                    "Password found in history - reuse attempted", false);
                return Page();
            }

            // 3. RESET PASSWORD
            var result = await _userManager.ResetPasswordAsync(user, Input.Code, Input.Password);
            if (result.Succeeded)
            {
                // 4. UPDATE LAST PASSWORD CHANGE DATE
                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                // 5. SAVE NEW PASSWORD TO HISTORY
                var newPasswordHash = user.PasswordHash!;
                await _passwordValidation.SavePasswordToHistoryAsync(user.Id, newPasswordHash);

                // 6. LOG SUCCESS
                await _auditLogService.LogActionAsync(user.Id, "Password Reset", 
                    "Password reset successfully via email link", true);

                _logger.LogInformation($"? User {user.Email} reset their password successfully");

                StatusMessage = "? Your password has been reset successfully. You can now login with your new password.";
                return RedirectToPage("/Account/Login");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogService.LogActionAsync(user.Id, "Password Reset Failed", 
                "Reset token invalid or expired", false);

            return Page();
        }
    }
}
