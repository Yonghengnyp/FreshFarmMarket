using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages.Account
{
    public class Verify2FAModel : PageModel
    {
        private readonly SignInManager<Member> _signInManager;
        private readonly UserManager<Member> _userManager;
        private readonly AuditLogService _auditLogService;
        private readonly IEmailService _emailService;
        private readonly ILogger<Verify2FAModel> _logger;

        public Verify2FAModel(
            SignInManager<Member> signInManager,
            UserManager<Member> userManager,
            AuditLogService auditLogService,
            IEmailService emailService,
            ILogger<Verify2FAModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _auditLogService = auditLogService;
            _emailService = emailService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        public string? Email { get; set; }
        public string? ReturnUrl { get; set; }

        [TempData]
        public string? StatusMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Please enter the verification code")]
            [StringLength(6, MinimumLength = 6, ErrorMessage = "Verification code must be exactly 6 digits")]
            [RegularExpression(@"^\d{6}$", ErrorMessage = "Please enter exactly 6 digits")]
            [DataType(DataType.Text)]
            [Display(Name = "Email Verification Code")]
            public string Code { get; set; } = string.Empty;
        }

        public IActionResult OnGet(string? email = null)
        {
            // Check if we have a valid 2FA session
            var sessionEmail = HttpContext.Session.GetString("2FA_Email");
            var sessionCode = HttpContext.Session.GetString("2FA_Code");
            var expiryString = HttpContext.Session.GetString("2FA_Expiry");

            if (string.IsNullOrEmpty(sessionEmail) || string.IsNullOrEmpty(sessionCode))
            {
                _logger.LogWarning("No 2FA session found");
                TempData["StatusMessage"] = "Session expired. Please login again.";
                return RedirectToPage("/Account/Login");
            }

            // Check if code has expired
            if (!string.IsNullOrEmpty(expiryString) && DateTime.TryParse(expiryString, out var expiry))
            {
                if (DateTime.UtcNow > expiry)
                {
                    _logger.LogWarning("2FA code expired");
                    HttpContext.Session.Remove("2FA_Code");
                    HttpContext.Session.Remove("2FA_Email");
                    HttpContext.Session.Remove("2FA_UserId");
                    HttpContext.Session.Remove("2FA_Expiry");
                    HttpContext.Session.Remove("2FA_RememberMe");
                    HttpContext.Session.Remove("2FA_ReturnUrl");
                    
                    TempData["StatusMessage"] = "Verification code expired. Please login again.";
                    return RedirectToPage("/Account/Login");
                }
            }

            Email = email ?? sessionEmail;
            ReturnUrl = HttpContext.Session.GetString("2FA_ReturnUrl") ?? "/Account/Home";

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Get 2FA session data
            var sessionCode = HttpContext.Session.GetString("2FA_Code");
            var sessionEmail = HttpContext.Session.GetString("2FA_Email");
            var sessionUserIdStr = HttpContext.Session.GetString("2FA_UserId");
            var expiryString = HttpContext.Session.GetString("2FA_Expiry");
            var rememberMeStr = HttpContext.Session.GetString("2FA_RememberMe");
            var returnUrl = HttpContext.Session.GetString("2FA_ReturnUrl") ?? "/Account/Home";

            if (string.IsNullOrEmpty(sessionCode) || string.IsNullOrEmpty(sessionEmail) || string.IsNullOrEmpty(sessionUserIdStr))
            {
                _logger.LogError("2FA session data missing");
                ModelState.AddModelError(string.Empty, "Session expired. Please login again.");
                return RedirectToPage("/Account/Login");
            }

            // Check if code has expired
            if (!string.IsNullOrEmpty(expiryString) && DateTime.TryParse(expiryString, out var expiry))
            {
                if (DateTime.UtcNow > expiry)
                {
                    _logger.LogWarning($"2FA code expired for {sessionEmail}");
                    
                    // Clear session
                    HttpContext.Session.Remove("2FA_Code");
                    HttpContext.Session.Remove("2FA_Email");
                    HttpContext.Session.Remove("2FA_UserId");
                    HttpContext.Session.Remove("2FA_Expiry");
                    HttpContext.Session.Remove("2FA_RememberMe");
                    HttpContext.Session.Remove("2FA_ReturnUrl");
                    
                    ModelState.AddModelError(string.Empty, "Verification code expired (5 minutes). Please login again.");
                    
                    if (int.TryParse(sessionUserIdStr, out var userId))
                    {
                        await _auditLogService.LogActionAsync(userId, "2FA Failed", "Code expired", false, "Code expired");
                    }
                    
                    return Page();
                }
            }

            Email = sessionEmail;
            ReturnUrl = returnUrl;

            // Strip spaces and hyphens from the input code
            var inputCode = Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            // Verify the code matches
            if (inputCode != sessionCode)
            {
                _logger.LogWarning("Invalid 2FA code attempt");
                
                if (int.TryParse(sessionUserIdStr, out var userId))
                {
                    await _auditLogService.LogActionAsync(userId, "2FA Failed", "Invalid code entered", false, "Invalid 2FA code");
                }
                
                ModelState.AddModelError(string.Empty, "Invalid verification code. Please check your email and try again.");
                return Page();
            }

            // Code is correct - get user and sign them in
            if (!int.TryParse(sessionUserIdStr, out var validUserId))
            {
                _logger.LogError("Invalid user ID in session");
                ModelState.AddModelError(string.Empty, "Session error. Please login again.");
                return RedirectToPage("/Account/Login");
            }

            var user = await _userManager.FindByIdAsync(validUserId.ToString());
            if (user == null)
            {
                _logger.LogError($"User not found: ID {validUserId}");
                ModelState.AddModelError(string.Empty, "User not found. Please login again.");
                return RedirectToPage("/Account/Login");
            }

            // Parse remember me
            bool rememberMe = bool.TryParse(rememberMeStr, out var remember) && remember;

            // Sign in the user
            await _signInManager.SignInAsync(user, isPersistent: rememberMe);

            _logger.LogInformation($"? User {user.Email} logged in successfully with email 2FA");

            // Update last login
            user.LastLoginDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _auditLogService.LogLoginAttemptAsync(user.Id, user.Email!, true, "Email 2FA verified");

            // Create session for backward compatibility
            HttpContext.Session.SetInt32("MemberId", user.Id);
            HttpContext.Session.SetString("MemberEmail", user.Email!);
            HttpContext.Session.SetString("MemberName", user.FullName);
            HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("o"));
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            // Clear 2FA session data
            HttpContext.Session.Remove("2FA_Code");
            HttpContext.Session.Remove("2FA_Email");
            HttpContext.Session.Remove("2FA_UserId");
            HttpContext.Session.Remove("2FA_Expiry");
            HttpContext.Session.Remove("2FA_RememberMe");
            HttpContext.Session.Remove("2FA_ReturnUrl");

            return LocalRedirect(ReturnUrl);
        }

        public async Task<IActionResult> OnPostResendCodeAsync()
        {
            // Get session data
            var sessionEmail = HttpContext.Session.GetString("2FA_Email");
            var sessionUserIdStr = HttpContext.Session.GetString("2FA_UserId");

            if (string.IsNullOrEmpty(sessionEmail) || string.IsNullOrEmpty(sessionUserIdStr))
            {
                TempData["StatusMessage"] = "Session expired. Please login again.";
                return RedirectToPage("/Account/Login");
            }

            // Generate new code
            var newCode = GenerateSixDigitCode();

            // Update session
            HttpContext.Session.SetString("2FA_Code", newCode);
            HttpContext.Session.SetString("2FA_Expiry", DateTime.UtcNow.AddMinutes(5).ToString("o"));

            // Send new code
            try
            {
                await _emailService.Send2FACodeAsync(sessionEmail, newCode);
                _logger.LogInformation($"?? New 2FA code sent to {sessionEmail}");

                if (int.TryParse(sessionUserIdStr, out var userId))
                {
                    await _auditLogService.LogActionAsync(userId, "2FA Code Resent",
                        $"New verification code sent to {sessionEmail}", true);
                }

                TempData["StatusMessage"] = "A new verification code has been sent to your email.";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resend 2FA code");
                TempData["StatusMessage"] = "Failed to send verification code. Please try again.";
            }

            return RedirectToPage(new { Email = sessionEmail });
        }

        private string GenerateSixDigitCode()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }
    }
}
