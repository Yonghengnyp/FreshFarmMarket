using FreshFarmMarket.Models;
using Microsoft.EntityFrameworkCore;
using WebApp_Core_Identity.Model;

namespace FreshFarmMarket.Services
{
    /// <summary>
    /// Service for logging user activities and security events
    /// </summary>
    public class AuditLogService
    {
        private readonly AuthDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditLogService(AuthDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Logs a user action to the database
        /// </summary>
        public async Task LogActionAsync(int? memberId, string action, string? details = null, bool isSuccess = true, string? errorMessage = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            
            var auditLog = new AuditLog
            {
                MemberId = memberId,
                Action = action,
                Details = details,
                IPAddress = GetClientIPAddress(),
                UserAgent = httpContext?.Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow,
                IsSuccess = isSuccess,
                ErrorMessage = errorMessage
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Logs user login attempt
        /// </summary>
        public async Task LogLoginAttemptAsync(int? memberId, string email, bool isSuccess, string? reason = null)
        {
            var details = $"Email: {email}";
            var action = isSuccess ? "Login Success" : "Login Failed";
            await LogActionAsync(memberId, action, details, isSuccess, reason);
        }

        /// <summary>
        /// Logs user logout
        /// </summary>
        public async Task LogLogoutAsync(int memberId, string email)
        {
            var details = $"Email: {email}";
            await LogActionAsync(memberId, "Logout", details);
        }

        /// <summary>
        /// Logs user registration
        /// </summary>
        public async Task LogRegistrationAsync(int memberId, string email)
        {
            var details = $"New member registered: {email}";
            await LogActionAsync(memberId, "Registration", details);
        }

        /// <summary>
        /// Logs password change
        /// </summary>
        public async Task LogPasswordChangeAsync(int memberId, string email)
        {
            var details = $"Password changed for: {email}";
            await LogActionAsync(memberId, "Password Change", details);
        }

        /// <summary>
        /// Logs account lockout
        /// </summary>
        public async Task LogAccountLockoutAsync(int memberId, string email, DateTime lockoutEnd)
        {
            var details = $"Account locked until: {lockoutEnd:yyyy-MM-dd HH:mm:ss} UTC";
            await LogActionAsync(memberId, "Account Lockout", details);
        }

        /// <summary>
        /// Logs data access (viewing encrypted data)
        /// </summary>
        public async Task LogDataAccessAsync(int memberId, string dataType)
        {
            var details = $"Accessed {dataType}";
            await LogActionAsync(memberId, "Data Access", details);
        }

        /// <summary>
        /// Gets recent audit logs for a member
        /// </summary>
        public async Task<List<AuditLog>> GetMemberLogsAsync(int memberId, int count = 50)
        {
            return await _context.AuditLogs
                .Where(log => log.MemberId == memberId)
                .OrderByDescending(log => log.Timestamp)
                .Take(count)
                .ToListAsync();
        }

        /// <summary>
        /// Detects multiple concurrent sessions
        /// </summary>
        public async Task<bool> DetectMultipleLoginsAsync(int memberId, TimeSpan timeWindow)
        {
            var cutoffTime = DateTime.UtcNow.Subtract(timeWindow);
            
            var recentLogins = await _context.AuditLogs
                .Where(log => log.MemberId == memberId 
                    && log.Action == "Login Success" 
                    && log.Timestamp >= cutoffTime)
                .ToListAsync();

            // Check if there are multiple logins from different IPs or User Agents
            var distinctSessions = recentLogins
                .GroupBy(log => new { log.IPAddress, log.UserAgent })
                .Count();

            return distinctSessions > 1;
        }

        /// <summary>
        /// Gets client IP address from HTTP context
        /// </summary>
        private string? GetClientIPAddress()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) return null;

            // Check for forwarded IP (when behind proxy/load balancer)
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }

            return httpContext.Connection.RemoteIpAddress?.ToString();
        }
    }
}
