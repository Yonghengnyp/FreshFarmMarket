using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using FreshFarmMarket.Models;
using FreshFarmMarket.Services;
using WebApp_Core_Identity.Model;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;

namespace FreshFarmMarket.Pages.Account
{
    public class HomeModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly EncryptionService _encryptionService;
        private readonly AuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<Member> _signInManager;

        public HomeModel(
            AuthDbContext context,
            EncryptionService encryptionService,
            AuditLogService auditLogService,
            IConfiguration configuration,
            SignInManager<Member> signInManager)
        {
            _context = context;
            _encryptionService = encryptionService;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        public Member? CurrentMember { get; set; }
        public string DecryptedCreditCard { get; set; } = string.Empty;
        public string MaskedCreditCard { get; set; } = string.Empty;
        public List<AuditLog> RecentActivities { get; set; } = new List<AuditLog>();
        public bool ShowDecryptedData { get; set; } = false;
        public int SessionTimeoutMinutes { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Get session timeout from configuration
            SessionTimeoutMinutes = _configuration.GetValue<int>("AccountPolicy:SessionTimeoutMinutes", 2);

            // Check if user is logged in
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                TempData["StatusMessage"] = "Please login to access this page.";
                return RedirectToPage("/Account/Login");
            }

            // Check for last activity timestamp
            var lastActivity = HttpContext.Session.GetString("LastActivity");
            if (!string.IsNullOrEmpty(lastActivity))
            {
                var lastActivityTime = DateTime.Parse(lastActivity);
                var sessionTimeout = TimeSpan.FromMinutes(SessionTimeoutMinutes);
                
                if (DateTime.UtcNow - lastActivityTime > sessionTimeout)
                {
                    await _auditLogService.LogActionAsync(memberId.Value, "Session Timeout", 
                        $"Session expired after {SessionTimeoutMinutes} minutes of inactivity", false);
                    HttpContext.Session.Clear();
                    TempData["StatusMessage"] = $"Your session has expired after {SessionTimeoutMinutes} minutes of inactivity. Please login again.";
                    return RedirectToPage("/Account/Login");
                }
            }

            // Update last activity timestamp
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            // Load member data
            CurrentMember = await _context.Members
                .FirstOrDefaultAsync(m => m.Id == memberId.Value);

            if (CurrentMember == null)
            {
                HttpContext.Session.Clear();
                TempData["StatusMessage"] = "Member not found. Please login again.";
                return RedirectToPage("/Account/Login");
            }

            // Check for multiple concurrent logins (security feature)
            var hasMultipleLogins = await _auditLogService.DetectMultipleLoginsAsync(
                memberId.Value, 
                TimeSpan.FromMinutes(30)
            );

            if (hasMultipleLogins)
            {
                TempData["MultipleLoginWarning"] = 
                    "?? Your account is logged in from multiple devices or browsers. " +
                    "If this wasn't you, please change your password immediately for security.";
                
                // Log the detection
                await _auditLogService.LogActionAsync(
                    memberId.Value, 
                    "Multiple Logins Detected", 
                    "User has active sessions from different devices/browsers", 
                    true
                );
            }

            // Decrypt credit card data
            DecryptedCreditCard = _encryptionService.Decrypt(CurrentMember.CreditCardNo);
            MaskedCreditCard = _encryptionService.MaskCreditCard(DecryptedCreditCard);

            // Load recent activities
            RecentActivities = await _auditLogService.GetMemberLogsAsync(memberId.Value, 10);

            return Page();
        }

        public async Task<IActionResult> OnPostShowDecryptedAsync()
        {
            // Get session timeout from configuration
            SessionTimeoutMinutes = _configuration.GetValue<int>("AccountPolicy:SessionTimeoutMinutes", 2);

            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                TempData["StatusMessage"] = "Please login to access this page.";
                return RedirectToPage("/Account/Login");
            }

            // Update last activity timestamp
            HttpContext.Session.SetString("LastActivity", DateTime.UtcNow.ToString("o"));

            CurrentMember = await _context.Members
                .FirstOrDefaultAsync(m => m.Id == memberId.Value);

            if (CurrentMember == null)
            {
                return RedirectToPage("/Account/Login");
            }

            DecryptedCreditCard = _encryptionService.Decrypt(CurrentMember.CreditCardNo);
            MaskedCreditCard = _encryptionService.MaskCreditCard(DecryptedCreditCard);
            ShowDecryptedData = true;

            // Log data access
            await _auditLogService.LogDataAccessAsync(memberId.Value, "Credit Card Number");

            RecentActivities = await _auditLogService.GetMemberLogsAsync(memberId.Value, 10);

            return Page();
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var email = HttpContext.Session.GetString("MemberEmail");

            if (memberId.HasValue && !string.IsNullOrEmpty(email))
            {
                await _auditLogService.LogLogoutAsync(memberId.Value, email);
            }

            // Clear Identity authentication (most important)
            await _signInManager.SignOutAsync();

            // Clear session data
            HttpContext.Session.Clear();

            // Clear remember me cookie
            Response.Cookies.Delete("MemberId");

            TempData["StatusMessage"] = "You have been logged out successfully.";
            return RedirectToPage("/Account/Login");
        }
    }
}
