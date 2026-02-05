using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using WebApp_Core_Identity.Model;

namespace FreshFarmMarket.Pages.Account
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<Member> _userManager;
        private readonly SignInManager<Member> _signInManager;
        private readonly AuthDbContext _context;
        private readonly PasswordValidationService _passwordValidationService;
        private readonly AuditLogService _auditLogService;
        private readonly IConfiguration _configuration;

        public ChangePasswordModel(
            UserManager<Member> userManager,
            SignInManager<Member> signInManager,
            AuthDbContext context,
            PasswordValidationService passwordValidationService,
            AuditLogService auditLogService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _passwordValidationService = passwordValidationService;
            _auditLogService = auditLogService;
            _configuration = configuration;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new InputModel();

        [TempData]
        public string? StatusMessage { get; set; }

        public string? MemberEmail { get; set; }
        public int DaysUntilExpiration { get; set; }
        public bool PasswordExpired { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Current password is required")]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; } = string.Empty;

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

        public async Task<IActionResult> OnGetAsync()
        {
            // Check if user is logged in
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                TempData["StatusMessage"] = "Please login to access this page.";
                return RedirectToPage("/Account/Login");
            }

            // Update last activity
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            // Load member data using Id instead of MemberId
            var member = await _userManager.FindByIdAsync(memberId.Value.ToString());

            if (member == null)
            {
                HttpContext.Session.Clear();
                return RedirectToPage("/Account/Login");
            }

            MemberEmail = member.Email;

            // Check password age
            var maxPasswordAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaxPasswordAgeDays", 90);
            if (member.LastPasswordChangeDate.HasValue)
            {
                var daysSinceChange = (DateTime.UtcNow - member.LastPasswordChangeDate.Value).Days;
                DaysUntilExpiration = maxPasswordAgeDays - daysSinceChange;
                PasswordExpired = DaysUntilExpiration <= 0;
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToPage("/Account/Login");
            }

            // Update last activity
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Load member using UserManager
            var member = await _userManager.FindByIdAsync(memberId.Value.ToString());

            if (member == null)
            {
                return RedirectToPage("/Account/Login");
            }

            MemberEmail = member.Email;

            // Check minimum password age
            var minPasswordAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinPasswordAgeMinutes", 5);
            if (member.LastPasswordChangeDate.HasValue)
            {
                var minutesSinceChange = (DateTime.UtcNow - member.LastPasswordChangeDate.Value).TotalMinutes;
                if (minutesSinceChange < minPasswordAgeMinutes)
                {
                    var remainingMinutes = (int)(minPasswordAgeMinutes - minutesSinceChange);
                    ModelState.AddModelError(string.Empty, 
                        $"You must wait {remainingMinutes} more minute(s) before changing your password again.");
                    return Page();
                }
            }

            // Validate new password strength
            var passwordValidation = _passwordValidationService.ValidatePassword(Input.NewPassword);
            if (!passwordValidation.IsValid)
            {
                foreach (var error in passwordValidation.Errors)
                {
                    ModelState.AddModelError(nameof(Input.NewPassword), error);
                }
                return Page();
            }

            // Use Identity's ChangePasswordAsync instead of BCrypt
            var result = await _userManager.ChangePasswordAsync(member, Input.CurrentPassword, Input.NewPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    if (error.Code == "PasswordMismatch")
                    {
                        ModelState.AddModelError(nameof(Input.CurrentPassword), "Current password is incorrect.");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                await _auditLogService.LogActionAsync(
                    memberId.Value,
                    "Password Change Failed",
                    "Password change failed",
                    false);
                return Page();
            }

            // Update last password change date
            member.LastPasswordChangeDate = DateTime.UtcNow;
            await _userManager.UpdateAsync(member);

            // Add to password history
            var passwordHistory = new PasswordHistory
            {
                MemberId = member.Id,
                PasswordHash = member.PasswordHash!,
                ChangedDate = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistory);
            await _context.SaveChangesAsync();

            // Update security stamp to invalidate old tokens/cookies
            await _userManager.UpdateSecurityStampAsync(member);

            // Refresh the sign-in to update the authentication cookie
            await _signInManager.RefreshSignInAsync(member);

            // Log password change
            await _auditLogService.LogPasswordChangeAsync(member.Id, member.Email!);

            StatusMessage = "Your password has been changed successfully!";
            return RedirectToPage("/Account/Home");
        }
    }
}
