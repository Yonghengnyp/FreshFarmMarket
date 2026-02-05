using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using FreshFarmMarket.Services;
using WebApp_Core_Identity.Model;
using Microsoft.Extensions.Logging;

namespace FreshFarmMarket.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly AuditLogService _auditLogService;
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(
            AuthDbContext context,
            AuditLogService auditLogService,
            ILogger<ForgotPasswordModel> logger)
        {
            _context = context;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email is required")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Find user by email
            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email == Input.Email);

            // Always show success message to prevent email enumeration
            if (member == null)
            {
                // Log the failed attempt
                await _auditLogService.LogActionAsync(
                    null,
                    "Password Reset Request",
                    $"Failed attempt for non-existent email: {Input.Email}",
                    false,
                    "Email not found");

                StatusMessage = "If an account exists with that email, a password reset link has been sent.";
                return RedirectToPage("/Account/Login");
            }

            // Check if account exists (without revealing it to prevent email enumeration)
            if (member != null)
            {
                // Check if account is locked
                if (member.LockoutEnd.HasValue && member.LockoutEnd.Value > DateTimeOffset.UtcNow)
                {
                    _logger.LogWarning($"Password reset requested for locked account: {Input.Email}");
                    // Don't reveal account is locked (security best practice)
                }
                else
                {
                    // Generate reset token
                    var resetToken = GenerateResetToken();
                    var resetTokenExpiry = DateTime.UtcNow.AddHours(1); // Token valid for 1 hour

                    // Store token in TempData (in production, use database or cache)
                    // For now, we'll create a simple URL with encoded token
                    var resetLink = Url.Page(
                        "/Account/ResetPassword",
                        pageHandler: null,
                        values: new { token = resetToken, email = Input.Email },
                        protocol: Request.Scheme);

                    // TODO: In production, send email with reset link
                    // await _emailService.SendPasswordResetEmailAsync(member.Email, resetLink);

                    // For demo purposes, store in TempData
                    TempData[$"ResetToken_{Input.Email}"] = resetToken;
                    TempData[$"ResetTokenExpiry_{Input.Email}"] = resetTokenExpiry.ToString("o");

                    // Log the request
                    await _auditLogService.LogActionAsync(
                        member.MemberId,
                        "Password Reset Request",
                        $"Password reset link generated",
                        true);

                    // FOR DEVELOPMENT/DEMO: Show the reset link
                    TempData["DemoResetLink"] = resetLink;

                    StatusMessage = "If an account exists with that email, a password reset link has been sent.";
                    return RedirectToPage("/Account/Login");
                }
            }

            return Page();
        }

        private string GenerateResetToken()
        {
            // Generate a cryptographically secure random token
            var tokenBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }
    }
}
