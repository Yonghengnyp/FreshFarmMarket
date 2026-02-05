using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly IEmailService _emailService;
        private readonly AuditLogService _auditLogService;
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(
            UserManager<Member> userManager,
            IEmailService emailService,
            AuditLogService auditLogService,
            ILogger<ForgotPasswordModel> logger)
        {
            _userManager = userManager;
            _emailService = emailService;
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
            [Display(Name = "Email Address")]
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
            var user = await _userManager.FindByEmailAsync(Input.Email);

            // SECURITY: Always show success message to prevent email enumeration attacks
            // Never reveal whether an account exists or not
            if (user == null)
            {
                _logger.LogWarning($"Password reset requested for non-existent email: {Input.Email}");
                await _auditLogService.LogActionAsync(null, "Password Reset Request Failed", 
                    $"Non-existent email: {Input.Email}", false, "Email not found");

                // Show success message anyway (security best practice)
                StatusMessage = "? If an account exists with that email address, a password reset link has been sent.";
                return RedirectToPage("/Account/Login");
            }

            // Check if account is locked
            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning($"Password reset requested for locked account: {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Password Reset Request Failed", 
                    "Account is locked out", false, "Account locked");

                // Don't reveal account is locked (security best practice)
                StatusMessage = "? If an account exists with that email address, a password reset link has been sent.";
                return RedirectToPage("/Account/Login");
            }

            // Generate password reset token using Identity
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Create reset link (token is URL-encoded automatically)
            var resetLink = Url.Page(
                "/Account/ResetPassword",
                pageHandler: null,
                values: new { code = resetToken, email = user.Email },
                protocol: Request.Scheme)!;

            // Send email with reset link
            try
            {
                await SendPasswordResetEmailAsync(user.Email!, resetLink);
                
                _logger.LogInformation($"? Password reset link sent to: {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Password Reset Request", 
                    "Reset link sent via email", true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to send password reset email to: {user.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Password Reset Request Failed", 
                    "Email sending failed", false, ex.Message);

                // Show generic error message
                ModelState.AddModelError(string.Empty, "An error occurred while processing your request. Please try again later.");
                return Page();
            }

            StatusMessage = "? If an account exists with that email address, a password reset link has been sent. Please check your inbox and spam folder.";
            return RedirectToPage("/Account/Login");
        }

        private async Task SendPasswordResetEmailAsync(string toEmail, string resetLink)
        {
            var subject = "Reset Your Password - Fresh Farm Market";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;'>
                        <div style='text-align: center; margin-bottom: 30px;'>
                            <h1 style='color: #28a745; margin-bottom: 10px;'>?? Fresh Farm Market</h1>
                            <h2 style='color: #555; font-size: 24px;'>Password Reset Request</h2>
                        </div>

                        <div style='background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;'>
                            <p style='margin: 0; font-size: 16px;'>
                                We received a request to reset your password. Click the button below to create a new password:
                            </p>
                        </div>

                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{resetLink}' 
                               style='display: inline-block; background-color: #28a745; color: white; padding: 15px 40px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold;'>
                                Reset Password
                            </a>
                        </div>

                        <div style='background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 20px 0;'>
                            <p style='margin: 0; color: #856404;'>
                                <strong>?? Important:</strong> This link will expire in <strong>1 hour</strong>.
                            </p>
                        </div>

                        <div style='background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;'>
                            <p style='margin: 0 0 10px 0; font-weight: bold;'>If the button doesn't work, copy and paste this link:</p>
                            <p style='margin: 0; word-break: break-all; font-size: 12px; color: #007bff;'>
                                {resetLink}
                            </p>
                        </div>

                        <div style='background-color: #d1ecf1; padding: 15px; border-radius: 5px; border-left: 4px solid #17a2b8; margin: 20px 0;'>
                            <p style='margin: 0; color: #0c5460;'>
                                <strong>?? Didn't request this?</strong> If you didn't request a password reset, please ignore this email or contact our support team immediately. Your account remains secure.
                            </p>
                        </div>

                        <hr style='margin: 30px 0; border: none; border-top: 1px solid #ddd;'>

                        <div style='text-align: center;'>
                            <p style='color: #666; font-size: 14px; margin: 10px 0;'>
                                <strong>Security Tips:</strong>
                            </p>
                            <ul style='text-align: left; color: #666; font-size: 12px; padding-left: 20px;'>
                                <li>Never share your password with anyone</li>
                                <li>Use a strong, unique password</li>
                                <li>Enable Two-Factor Authentication for extra security</li>
                                <li>Be cautious of phishing emails</li>
                            </ul>
                        </div>

                        <hr style='margin: 30px 0; border: none; border-top: 1px solid #ddd;'>

                        <p style='color: #999; font-size: 11px; text-align: center; margin: 20px 0;'>
                            This is an automated email from Fresh Farm Market.<br>
                            Please do not reply to this email.
                        </p>
                    </div>
                </body>
                </html>
            ";

            await _emailService.SendEmailAsync(toEmail, subject, body);
        }
    }
}
