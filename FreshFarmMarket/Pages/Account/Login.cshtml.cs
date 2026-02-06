using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;

namespace FreshFarmMarket.Pages.Account
{
    [ValidateAntiForgeryToken]
    public class LoginModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly SignInManager<Member> _signInManager;
        private readonly AuditLogService _auditLogService;
        private readonly RecaptchaService _recaptchaService;
        private readonly IEmailService _emailService;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(
            UserManager<Member> userManager,
            SignInManager<Member> signInManager,
            AuditLogService auditLogService,
            RecaptchaService recaptchaService,
            IEmailService emailService,
            ILogger<LoginModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _auditLogService = auditLogService;
            _recaptchaService = recaptchaService;
            _emailService = emailService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public string? ReturnUrl { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email is required")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Remember Me")]
            public bool RememberMe { get; set; }

            [Required(ErrorMessage = "Please complete the reCAPTCHA verification")]
            public string RecaptchaToken { get; set; } = string.Empty;
        }

        public void OnGet(string? returnUrl = null)
        {
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            ReturnUrl = returnUrl ?? Url.Content("~/Account/Home");

            _logger.LogInformation("=== LOGIN ATTEMPT STARTED ===");
            _logger.LogInformation($"Email: {Input.Email}");

            // Server-side reCAPTCHA validation
            var recaptchaResult = await _recaptchaService.ValidateAsync(Input.RecaptchaToken, "login");
            if (!recaptchaResult.Success)
            {
                _logger.LogWarning($"reCAPTCHA validation failed for {Input.Email}");
                ModelState.AddModelError(string.Empty, recaptchaResult.ErrorMessage ?? "reCAPTCHA validation failed. Please try again.");
                await _auditLogService.LogActionAsync(null, "Login Failed", 
                    $"reCAPTCHA validation failed for {Input.Email}: {recaptchaResult.ErrorMessage}", false, "reCAPTCHA failed");
                return Page();
            }
            _logger.LogInformation("? reCAPTCHA validated");

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("ModelState invalid");
                return Page();
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(Input.Email);
            
            if (user == null)
            {
                _logger.LogWarning($"User not found: {Input.Email}");
                await _auditLogService.LogActionAsync(null, "Login Failed", $"User not found: {Input.Email}", false, "User not found");
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return Page();
            }

            // Check password first (don't sign in yet if 2FA is enabled)
            var passwordCheck = await _signInManager.CheckPasswordSignInAsync(user, Input.Password, lockoutOnFailure: true);

            if (passwordCheck.IsLockedOut)
            {
                _logger.LogWarning($"Account locked: {Input.Email}");
                await _auditLogService.LogActionAsync(user.Id, "Login Failed", "Account locked", false, "Account locked");
                ModelState.AddModelError(string.Empty, "Account locked due to multiple failed attempts. Please try again later.");
                return Page();
            }

            if (!passwordCheck.Succeeded)
            {
                // Invalid password
                _logger.LogWarning($"Invalid password for {Input.Email}");
                await _auditLogService.LogActionAsync(user?.Id, "Login Failed", "Invalid password", false, "Invalid password");
                
                var failedCount = await _userManager.GetAccessFailedCountAsync(user!);
                var maxAttempts = _userManager.Options.Lockout.MaxFailedAccessAttempts;
                var remaining = maxAttempts - failedCount;
                
                ModelState.AddModelError(string.Empty, $"Invalid email or password. {remaining} attempt(s) remaining.");
                return Page();
            }

            // Password is correct - now check if 2FA is enabled
            if (user.TwoFactorEnabled)
            {
                _logger.LogInformation($"?? 2FA required for {Input.Email}");
                
                // Generate a 6-digit code
                var code = GenerateSixDigitCode();
                
                // Store code in session with expiration (5 minutes)
                HttpContext.Session.SetString("2FA_Code", code);
                HttpContext.Session.SetString("2FA_Email", user.Email!);
                HttpContext.Session.SetString("2FA_UserId", user.Id.ToString());
                HttpContext.Session.SetString("2FA_Expiry", DateTime.UtcNow.AddMinutes(5).ToString("o"));
                HttpContext.Session.SetString("2FA_RememberMe", Input.RememberMe.ToString());
                HttpContext.Session.SetString("2FA_ReturnUrl", ReturnUrl);
                
                // Send code via email
                try
                {
                    await _emailService.Send2FACodeAsync(user.Email!, code);
                    _logger.LogInformation($"?? 2FA code sent to {user.Email}");
                    
                    await _auditLogService.LogActionAsync(user.Id, "2FA Code Sent", 
                        $"6-digit verification code sent to {user.Email}", true);
                    
                    TempData["StatusMessage"] = "A 6-digit verification code has been sent to your email.";
                    
                    // Redirect to 2FA verification page
                    return RedirectToPage("/Account/Verify2FA", new { 
                        Email = user.Email
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send 2FA code");
                    ModelState.AddModelError(string.Empty, "Failed to send verification code. Please try again.");
                    return Page();
                }
            }

            // No 2FA - proceed with normal sign in
            var result = await _signInManager.PasswordSignInAsync(
                user.UserName!,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: false // Already checked above
            );

            if (result.Succeeded)
            {
                _logger.LogInformation($"? User {Input.Email} logged in successfully");
                
                // Update last login
                user.LastLoginDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                
                await _auditLogService.LogLoginAttemptAsync(user.Id, user.Email!, true);
                
                // Create session for backward compatibility
                HttpContext.Session.SetInt32("MemberId", user.Id);
                HttpContext.Session.SetString("MemberEmail", user.Email!);
                HttpContext.Session.SetString("MemberName", user.FullName);
                HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("o"));
                HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));
                
                return LocalRedirect(ReturnUrl);
            }

            // Shouldn't reach here, but handle it
            ModelState.AddModelError(string.Empty, "Login failed. Please try again.");
            return Page();
        }

        private string GenerateSixDigitCode()
        {
            // Generate a random 6-digit code
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        private bool IsValidFileType(IFormFile file)
        {
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".pdf", ".docx" };
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
               return allowedExtensions.Contains(extension);
           }
    }
}
