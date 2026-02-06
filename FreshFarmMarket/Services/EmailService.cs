using System.Net;
using System.Net.Mail;

namespace FreshFarmMarket.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
        Task Send2FACodeAsync(string toEmail, string code);
    }

    public class EmailService : IEmailService
    {
        private readonly ILogger<EmailService> _logger;
        private readonly IConfiguration _configuration;

        public EmailService(ILogger<EmailService> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                // Check if SMTP is configured
                var smtpHost = _configuration["Email:SmtpHost"];
                var smtpPortStr = _configuration["Email:SmtpPort"];
                var username = _configuration["Email:Username"];
                var password = _configuration["Email:Password"];
                var fromEmail = _configuration["Email:FromEmail"];
                var fromName = _configuration["Email:FromName"] ?? "Fresh Farm Market";

                // If SMTP not configured, log to console (development mode)
                if (string.IsNullOrEmpty(smtpHost) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    _logger.LogWarning("?? SMTP not configured - Email will be logged to console only");
                    _logger.LogInformation("========================================");
                    _logger.LogInformation($"?? EMAIL TO: {toEmail}");
                    _logger.LogInformation($"?? SUBJECT: {subject}");
                    _logger.LogInformation("?? EMAIL BODY GENERATED BUT NOT LOGGED FOR SECURITY.");
                    _logger.LogInformation("========================================");
                    
                    // Extract 6-digit code if this is a 2FA email
                    if (subject.Contains("2FA") || subject.Contains("Verification Code"))
                    {
                        var codeMatch = System.Text.RegularExpressions.Regex.Match(body, @"\b\d{6}\b");
                        if (codeMatch.Success)
                        {
                            _logger.LogWarning("========================================");
                            // Do not log the actual 2FA/verification code to avoid storing sensitive data in logs
                            _logger.LogWarning("?? A 6-DIGIT VERIFICATION CODE WAS GENERATED (value not logged for security).");
                            _logger.LogWarning("========================================");
                        }
                    }
                    
                    return;
                }

                // Production mode - send actual email via SMTP
                _logger.LogInformation($"?? Sending email to {toEmail} via SMTP...");

                int smtpPort = 587; // Default Gmail SMTP port
                if (!string.IsNullOrEmpty(smtpPortStr) && int.TryParse(smtpPortStr, out int parsedPort))
                {
                    smtpPort = parsedPort;
                }

                using var smtpClient = new SmtpClient(smtpHost)
                {
                    Port = smtpPort,
                    Credentials = new NetworkCredential(username, password),
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false
                };

                using var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail ?? "noreply@freshfarmmarket.com", fromName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true,
                };
                
                mailMessage.To.Add(toEmail);

                await smtpClient.SendMailAsync(mailMessage);

                _logger.LogInformation($"? Email sent successfully to {toEmail}");
            }
            catch (SmtpException smtpEx)
            {
                _logger.LogError(smtpEx, $"? SMTP error sending email to {toEmail}");
                _logger.LogError($"SMTP Error: {smtpEx.StatusCode} - {smtpEx.Message}");
                
                // Log to console as fallback
                _logger.LogWarning("========================================");
                _logger.LogWarning($"?? FALLBACK - EMAIL TO: {toEmail}");
                _logger.LogWarning($"?? SUBJECT: {subject}");
                
                // Extract 6-digit code if this is a 2FA email
                if (subject.Contains("2FA") || subject.Contains("Verification Code"))
                {
                    var codeMatch = System.Text.RegularExpressions.Regex.Match(body, @"\b\d{6}\b");
                    if (codeMatch.Success)
                    {
                        // Do not log the actual 2FA code to avoid storing sensitive data in logs
                        _logger.LogWarning("?? A 6-DIGIT 2FA/verification code was detected in the email body (not logged for security).");
                    }
                }
                _logger.LogWarning("========================================");
                
                throw new Exception($"Failed to send email: {smtpEx.Message}", smtpEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"? Unexpected error sending email to {toEmail}");
                throw;
            }
        }

        public async Task Send2FACodeAsync(string toEmail, string code)
        {
            var subject = "Your 2FA Verification Code - Fresh Farm Market";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;'>
                        <h2 style='color: #28a745;'>?? Fresh Farm Market</h2>
                        <h3>Two-Factor Authentication Code</h3>
                        <p>Your verification code is:</p>
                        <div style='background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 10px; border-radius: 5px; margin: 20px 0; color: #007bff;'>
                            {code}
                        </div>
                        <p><strong>This code will expire in 5 minutes.</strong></p>
                        <p>If you didn't request this code, please ignore this email or contact support immediately.</p>
                        <hr style='margin: 30px 0; border: 1px solid #ddd;'>
                        <p style='color: #666; font-size: 12px;'>
                            This is an automated message from Fresh Farm Market. Please do not reply to this email.
                        </p>
                    </div>
                </body>
                </html>
            ";

            await SendEmailAsync(toEmail, subject, body);
        }
    }
}
