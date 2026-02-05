using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using WebApp_Core_Identity.Model;
using BC = BCrypt.Net.BCrypt;

namespace FreshFarmMarket.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly PasswordValidationService _passwordValidationService;
        private readonly AuditLogService _auditLogService;
        private readonly IConfiguration _configuration;

        public ResetPasswordModel(
            AuthDbContext context,
            PasswordValidationService passwordValidationService,
            AuditLogService auditLogService,
            IConfiguration configuration)
        {
            _context = context;
            _passwordValidationService = passwordValidationService;
            _auditLogService = auditLogService;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public string Email { get; set; } = string.Empty;
        public bool TokenExpired { get; set; }

        public class InputModel
        {
            [Required]
            public string Email { get; set; } = string.Empty;

            [Required]
            public string Token { get; set; } = string.Empty;

            [Required(ErrorMessage = "New password is required")]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string NewPassword { get; set; } = string.Empty;

            [Required(ErrorMessage = "Please confirm your new password")]
            [DataType(DataType.Password)]
            [Compare("NewPassword", ErrorMessage = "New password and confirmation password do not match")]
            [Display(Name = "Confirm New Password")]
            public string ConfirmPassword { get; set; } = string.Empty;
        }

        public IActionResult OnGet(string? token, string? email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                TempData["StatusMessage"] = "Invalid password reset link.";
                return RedirectToPage("/Account/Login");
            }

            // Validate token from TempData
            var storedToken = TempData.Peek($"ResetToken_{email}") as string;
            var storedExpiry = TempData.Peek($"ResetTokenExpiry_{email}") as string;

            if (string.IsNullOrEmpty(storedToken) || string.IsNullOrEmpty(storedExpiry))
            {
                TokenExpired = true;
                Email = email;
                return Page();
            }

            if (!DateTime.TryParse(storedExpiry, out var expiryDate) || DateTime.UtcNow > expiryDate)
            {
                TokenExpired = true;
                Email = email;
                return Page();
            }

            if (storedToken != token)
            {
                TempData["StatusMessage"] = "Invalid password reset link.";
                return RedirectToPage("/Account/Login");
            }

            // Valid token
            Email = email;
            Input.Email = email;
            Input.Token = token;
            TokenExpired = false;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                Email = Input.Email;
                return Page();
            }

            // Validate token
            var storedToken = TempData.Peek($"ResetToken_{Input.Email}") as string;
            var storedExpiry = TempData.Peek($"ResetTokenExpiry_{Input.Email}") as string;

            if (string.IsNullOrEmpty(storedToken) || string.IsNullOrEmpty(storedExpiry))
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired reset token.");
                Email = Input.Email;
                TokenExpired = true;
                return Page();
            }

            if (!DateTime.TryParse(storedExpiry, out var expiryDate) || DateTime.UtcNow > expiryDate)
            {
                ModelState.AddModelError(string.Empty, "This reset link has expired. Please request a new one.");
                Email = Input.Email;
                TokenExpired = true;
                return Page();
            }

            if (storedToken != Input.Token)
            {
                ModelState.AddModelError(string.Empty, "Invalid reset token.");
                Email = Input.Email;
                return Page();
            }

            // Find member
            var member = await _context.Members
                .Include(m => m.PasswordHistories)
                .FirstOrDefaultAsync(m => m.Email == Input.Email);

            if (member == null)
            {
                await _auditLogService.LogActionAsync(
                    null,
                    "Password Reset Failed",
                    $"Member not found for email: {Input.Email}",
                    false,
                    "Member not found");

                ModelState.AddModelError(string.Empty, "Unable to reset password.");
                Email = Input.Email;
                return Page();
            }

            // Validate new password strength
            var passwordValidation = _passwordValidationService.ValidatePassword(Input.NewPassword);
            if (!passwordValidation.IsValid)
            {
                foreach (var error in passwordValidation.Errors)
                {
                    ModelState.AddModelError(nameof(Input.NewPassword), error);
                }
                Email = Input.Email;
                return Page();
            }

            // Check password history
            var passwordHistoryCount = _configuration.GetValue<int>("PasswordPolicy:PasswordHistoryCount", 2);
            var recentPasswords = member.PasswordHistories
                .OrderByDescending(ph => ph.ChangedDate)
                .Take(passwordHistoryCount)
                .ToList();

            foreach (var oldPassword in recentPasswords)
            {
                if (BC.Verify(Input.NewPassword, oldPassword.PasswordHash))
                {
                    ModelState.AddModelError(nameof(Input.NewPassword),
                        $"You cannot reuse your last {passwordHistoryCount} passwords.");
                    await _auditLogService.LogActionAsync(
                        member.MemberId,
                        "Password Reset Failed",
                        "Password reuse attempted",
                        false);
                    Email = Input.Email;
                    return Page();
                }
            }

            // Update password
            var hashedPassword = BC.HashPassword(Input.NewPassword);
            // Update member password
            member.PasswordHash = hashedPassword;
            member.LastPasswordChangeDate = DateTime.UtcNow;
            
            // Unlock account if it was locked (using Identity properties)
            member.LockoutEnd = null;
            member.LockoutEnabled = false;
            member.AccessFailedCount = 0;
            
            await _context.SaveChangesAsync();

            // Clear the reset token from TempData
            TempData.Remove($"ResetToken_{Input.Email}");
            TempData.Remove($"ResetTokenExpiry_{Input.Email}");

            // Log password reset
            await _auditLogService.LogActionAsync(
                member.MemberId,
                "Password Reset",
                $"Password reset successfully for {member.Email}",
                true);

            StatusMessage = "Your password has been reset successfully! You can now login with your new password.";
            return RedirectToPage("/Account/Login");
        }
    }
}
