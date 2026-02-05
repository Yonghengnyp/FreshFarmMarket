using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using WebApp_Core_Identity.Model;
using BC = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Logging;

namespace FreshFarmMarket.Pages.Account
{
    [ValidateAntiForgeryToken]
    public class RegisterModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly SignInManager<Member> _signInManager;
        private readonly AuthDbContext _context;
        private readonly EncryptionService _encryptionService;
        private readonly PasswordValidationService _passwordValidationService;
        private readonly AuditLogService _auditLogService;
        private readonly IWebHostEnvironment _environment;
        private readonly RecaptchaService _recaptchaService;
        private readonly ILogger<RegisterModel> _logger;

        public RegisterModel(
            UserManager<Member> userManager,
            SignInManager<Member> signInManager,
            AuthDbContext context,
            EncryptionService encryptionService,
            PasswordValidationService passwordValidationService,
            AuditLogService auditLogService,
            IWebHostEnvironment environment,
            RecaptchaService recaptchaService,
            ILogger<RegisterModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _encryptionService = encryptionService;
            _passwordValidationService = passwordValidationService;
            _auditLogService = auditLogService;
            _environment = environment;
            _recaptchaService = recaptchaService;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public string? PasswordStrength { get; set; }
        public int PasswordStrengthScore { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Full Name is required")]
            [StringLength(100, ErrorMessage = "Full Name cannot exceed 100 characters")]
            [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Full Name can only contain letters and spaces")]
            [Display(Name = "Full Name")]
            public string FullName { get; set; } = string.Empty;

            [Required(ErrorMessage = "Credit Card Number is required")]
            [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card Number must be 16 digits")]
            [Display(Name = "Credit Card Number")]
            public string CreditCardNo { get; set; } = string.Empty;

            [Required(ErrorMessage = "Gender is required")]
            [Display(Name = "Gender")]
            public string Gender { get; set; } = string.Empty;

            [Required(ErrorMessage = "Mobile Number is required")]
            [RegularExpression(@"^[689]\d{7}$", ErrorMessage = "Please enter a valid Singapore mobile number")]
            [Display(Name = "Mobile Number")]
            public string MobileNo { get; set; } = string.Empty;

            [Required(ErrorMessage = "Delivery Address is required")]
            [StringLength(500, ErrorMessage = "Delivery Address cannot exceed 500 characters")]
            [Display(Name = "Delivery Address")]
            public string DeliveryAddress { get; set; } = string.Empty;

            [Required(ErrorMessage = "Email is required")]
            [EmailAddress(ErrorMessage = "Please enter a valid email address")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "Password is required")]
            [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = string.Empty;

            [Required(ErrorMessage = "Please confirm your password")]
            [DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "Password and confirmation password do not match")]
            [Display(Name = "Confirm Password")]
            public string ConfirmPassword { get; set; } = string.Empty;

            [Display(Name = "Profile Photo")]
            public IFormFile? Photo { get; set; }

            [StringLength(1000, ErrorMessage = "About Me cannot exceed 1000 characters")]
            [Display(Name = "About Me")]
            public string? AboutMe { get; set; }

            [Required(ErrorMessage = "Please complete the reCAPTCHA verification")]
            public string RecaptchaToken { get; set; } = string.Empty;
        }

        public void OnGet()
        {
            _logger.LogInformation("Registration page loaded");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("=== REGISTRATION STARTED ===");
            _logger.LogInformation($"Email: {Input.Email}");

            try
            {
                // Step 1: reCAPTCHA validation
                _logger.LogInformation("Step 1: Validating reCAPTCHA...");
                var recaptchaResult = await _recaptchaService.ValidateAsync(Input.RecaptchaToken, "register");
                if (!recaptchaResult.Success)
                {
                    _logger.LogWarning($"reCAPTCHA validation failed: {recaptchaResult.ErrorMessage}");
                    ModelState.AddModelError(string.Empty, recaptchaResult.ErrorMessage ?? "reCAPTCHA validation failed. Please try again.");
                    return Page();
                }
                _logger.LogInformation("? reCAPTCHA validated successfully");

                // Step 2: Password validation
                _logger.LogInformation("Step 2: Validating password strength...");
                var passwordValidation = _passwordValidationService.ValidatePassword(Input.Password);
                if (!passwordValidation.IsValid)
                {
                    _logger.LogWarning("Password validation failed");
                    foreach (var error in passwordValidation.Errors)
                    {
                        _logger.LogWarning($"Password error: {error}");
                        ModelState.AddModelError(nameof(Input.Password), error);
                    }
                    return Page();
                }
                _logger.LogInformation($"? Password validated - Strength: {passwordValidation.StrengthLevel}");

                PasswordStrength = passwordValidation.StrengthLevel;
                PasswordStrengthScore = passwordValidation.StrengthScore;

                // Step 3: Model state validation
                if (!ModelState.IsValid)
                {
                    _logger.LogWarning("ModelState is invalid");
                    foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                    {
                        _logger.LogWarning($"Validation error: {error.ErrorMessage}");
                    }
                    return Page();
                }
                _logger.LogInformation("? Model validation passed");

                // Step 4: Check for duplicate email - Identity handles this automatically
                _logger.LogInformation("Step 4: Identity will check for duplicate email...");

                // Step 5: Handle photo upload
                string? photoPath = null;
                if (Input.Photo != null)
                {
                    _logger.LogInformation($"Step 5: Uploading photo - {Input.Photo.FileName} ({Input.Photo.Length} bytes)");
                    var uploadResult = await UploadPhotoAsync(Input.Photo);
                    if (!uploadResult.Success)
                    {
                        _logger.LogError($"Photo upload failed: {uploadResult.ErrorMessage}");
                        ModelState.AddModelError(nameof(Input.Photo), uploadResult.ErrorMessage!);
                        return Page();
                    }
                    photoPath = uploadResult.FilePath;
                    _logger.LogInformation($"? Photo uploaded: {photoPath}");
                }
                else
                {
                    _logger.LogInformation("Step 5: No photo uploaded (optional)");
                }

                // Step 6: Encrypt sensitive data
                _logger.LogInformation("Step 6: Encrypting credit card number...");
                string encryptedCreditCard;
                try
                {
                    encryptedCreditCard = _encryptionService.Encrypt(Input.CreditCardNo);
                    _logger.LogInformation("? Credit card encrypted successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to encrypt credit card");
                    ModelState.AddModelError(string.Empty, "An error occurred during registration. Please try again.");
                    return Page();
                }

                // Step 7: Create member object
                _logger.LogInformation("Step 7: Creating member object...");
                var member = new Member
                {
                    UserName = Input.Email, // Identity requires UserName
                    Email = Input.Email,
                    FullName = Input.FullName,
                    CreditCardNo = encryptedCreditCard,
                    Gender = Input.Gender,
                    MobileNo = Input.MobileNo,
                    DeliveryAddress = Input.DeliveryAddress,
                    PhotoPath = photoPath,
                    AboutMe = Input.AboutMe,
                    CreatedDate = DateTime.UtcNow,
                    LastPasswordChangeDate = DateTime.UtcNow,
                    TwoFactorEnabled = true, // ?? FORCE 2FA ON - Always required
                    LockoutEnabled = true // Enable lockout protection
                };
                _logger.LogInformation("? Member object created with 2FA REQUIRED");

                // Step 8: Create user with Identity (this handles password hashing automatically)
                _logger.LogInformation("Step 8: Creating user with Identity...");
                var result = await _userManager.CreateAsync(member, Input.Password);

                if (!result.Succeeded)
                {
                    _logger.LogError("Failed to create user with Identity");
                    foreach (var error in result.Errors)
                    {
                        _logger.LogError($"Identity error: {error.Description}");
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    
                    // Delete uploaded photo if user creation fails
                    if (photoPath != null)
                    {
                        DeletePhoto(photoPath);
                    }
                    
                    await _auditLogService.LogActionAsync(null, "Registration Failed", 
                        $"Email: {Input.Email}, Identity errors", false, string.Join(", ", result.Errors.Select(e => e.Description)));
                    return Page();
                }

                _logger.LogInformation($"? User created successfully! MemberId: {member.Id}");

                // Step 9: Save password to history using PasswordValidationService
                _logger.LogInformation("Step 9: Saving initial password to history...");
                try
                {
                    await _passwordValidationService.SavePasswordToHistoryAsync(member.Id, member.PasswordHash!);
                    _logger.LogInformation("? Initial password saved to history");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to save password history (non-critical)");
                    // Don't fail registration if password history fails
                }

                // Step 10: Log successful registration
                _logger.LogInformation("Step 10: Creating audit log...");
                try
                {
                    await _auditLogService.LogRegistrationAsync(member.Id, member.Email);
                    _logger.LogInformation("? Audit log created");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to create audit log (non-critical)");
                    // Don't fail registration if audit log fails
                }

                // Success!
                _logger.LogInformation("=== REGISTRATION COMPLETED SUCCESSFULLY ===");
                _logger.LogInformation($"MemberId: {member.Id}, Email: {member.Email}");

                // Sign in the user and redirect to enable 2FA
                await _signInManager.SignInAsync(member, isPersistent: false);
                
                // Create session
                HttpContext.Session.SetInt32("MemberId", member.Id);
                HttpContext.Session.SetString("MemberEmail", member.Email);
                HttpContext.Session.SetString("MemberName", member.FullName);
                HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("o"));
                HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));
                
                TempData["StatusMessage"] = "Registration successful! Please set up Two-Factor Authentication to secure your account.";
                return RedirectToPage("/Account/Enable2FA");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during registration");
                _logger.LogError($"Error: {ex.Message}");
                _logger.LogError($"Stack trace: {ex.StackTrace}");
                
                ModelState.AddModelError(string.Empty, "An unexpected error occurred. Please try again.");
                await _auditLogService.LogActionAsync(null, "Registration Failed", 
                    $"Email: {Input.Email}, Unexpected error", false, ex.Message);
                return Page();
            }
        }

        private async Task<(bool Success, string? FilePath, string? ErrorMessage)> UploadPhotoAsync(IFormFile photo)
        {
            try
            {
                // Validate file extension
                var extension = Path.GetExtension(photo.FileName).ToLowerInvariant();
                var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp" };
                
                if (!allowedExtensions.Contains(extension))
                {
                    return (false, null, "Only image files are allowed (JPG, JPEG, PNG, GIF, BMP, WEBP)");
                }

                // Validate file size (max 5MB)
                if (photo.Length > 5 * 1024 * 1024)
                {
                    return (false, null, "File size cannot exceed 5MB");
                }

                // Validate content type
                var allowedContentTypes = new[] { "image/jpeg", "image/jpg", "image/png", "image/gif", "image/bmp", "image/webp" };
                if (!allowedContentTypes.Contains(photo.ContentType.ToLowerInvariant()))
                {
                    return (false, null, "Invalid image file type");
                }

                // Generate unique filename
                var fileName = $"{Guid.NewGuid()}{extension}";
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "photos");
                
                // Create directory if it doesn't exist
                Directory.CreateDirectory(uploadsFolder);
                
                var filePath = Path.Combine(uploadsFolder, fileName);
                var relativePath = Path.Combine("uploads", "photos", fileName).Replace("\\", "/");

                using var fileStream = new FileStream(filePath, FileMode.Create);
                await photo.CopyToAsync(fileStream);
                
                _logger.LogInformation($"Photo saved to: {filePath}");
                return (true, relativePath, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading photo");
                return (false, null, $"Error uploading file: {ex.Message}");
            }
        }

        private void DeletePhoto(string photoPath)
        {
            try
            {
                var fullPath = Path.Combine(_environment.WebRootPath, photoPath);
                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                    _logger.LogInformation($"Deleted photo: {fullPath}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Failed to delete photo: {photoPath}");
            }
        }
    }
}
