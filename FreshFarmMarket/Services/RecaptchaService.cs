using System.Text.Json;

namespace FreshFarmMarket.Services
{
    public class RecaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<RecaptchaService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;

        public RecaptchaService(
            IConfiguration configuration,
            ILogger<RecaptchaService> logger,
            IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<RecaptchaValidationResult> ValidateAsync(string token, string action = "")
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("reCAPTCHA validation failed: Token is empty");
                return new RecaptchaValidationResult 
                { 
                    Success = false, 
                    ErrorMessage = "reCAPTCHA token is missing. Please refresh the page and try again." 
                };
            }

            try
            {
                var secretKey = _configuration["ReCaptcha:SecretKey"];
                var minScore = _configuration.GetValue<double>("ReCaptcha:MinScore", 0.5);
                var bypassInDevelopment = _configuration.GetValue<bool>("ReCaptcha:BypassInDevelopment", false);

                if (string.IsNullOrWhiteSpace(secretKey))
                {
                    _logger.LogError("reCAPTCHA SecretKey is not configured");
                    return new RecaptchaValidationResult 
                    { 
                        Success = false, 
                        ErrorMessage = "reCAPTCHA is not properly configured" 
                    };
                }

                var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(10);

                var requestUrl = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}";
                
                var response = await httpClient.PostAsync(requestUrl, null);
                
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"reCAPTCHA API returned status code: {response.StatusCode}");
                    return new RecaptchaValidationResult 
                    { 
                        Success = false, 
                        ErrorMessage = "Failed to verify reCAPTCHA with Google. Please try again." 
                    };
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                _logger.LogInformation($"reCAPTCHA response: {jsonResponse}");

                using var document = JsonDocument.Parse(jsonResponse);
                var root = document.RootElement;

                // Check if the response has 'success' property
                if (!root.TryGetProperty("success", out var successProperty))
                {
                    _logger.LogError("reCAPTCHA response missing 'success' property");
                    return new RecaptchaValidationResult 
                    { 
                        Success = false, 
                        ErrorMessage = "Invalid reCAPTCHA response format" 
                    };
                }

                var success = successProperty.GetBoolean();

                // Log error codes if present
                if (root.TryGetProperty("error-codes", out var errorCodesProperty))
                {
                    var errorCodes = errorCodesProperty.EnumerateArray()
                        .Select(e => e.GetString())
                        .ToList();
                    
                    if (errorCodes.Any())
                    {
                        var errorCodesStr = string.Join(", ", errorCodes);
                        _logger.LogWarning($"reCAPTCHA error codes: {errorCodesStr}");
                        
                        // If browser-error in development and bypass is enabled, allow it
                        if (bypassInDevelopment && errorCodes.Contains("browser-error"))
                        {
                            _logger.LogWarning("Bypassing browser-error in development mode");
                            return new RecaptchaValidationResult 
                            { 
                                Success = true,
                                Score = 1.0,
                                ErrorMessage = null
                            };
                        }
                        
                        return new RecaptchaValidationResult 
                        { 
                            Success = false, 
                            ErrorMessage = $"reCAPTCHA validation failed: {GetErrorMessage(errorCodes)}" 
                        };
                    }
                }

                if (!success)
                {
                    _logger.LogWarning("reCAPTCHA validation returned success=false");
                    return new RecaptchaValidationResult 
                    { 
                        Success = false, 
                        ErrorMessage = "reCAPTCHA validation failed. Please try again." 
                    };
                }

                // For reCAPTCHA v3, check score and action
                if (root.TryGetProperty("score", out var scoreProperty))
                {
                    var score = scoreProperty.GetDouble();
                    _logger.LogInformation($"reCAPTCHA v3 score: {score} (minimum: {minScore})");

                    // Optionally verify action matches
                    if (!string.IsNullOrEmpty(action) && root.TryGetProperty("action", out var actionProperty))
                    {
                        var returnedAction = actionProperty.GetString();
                        if (returnedAction != action)
                        {
                            _logger.LogWarning($"reCAPTCHA action mismatch: expected '{action}', got '{returnedAction}'");
                        }
                    }

                    if (score < minScore)
                    {
                        _logger.LogWarning($"reCAPTCHA score {score} below minimum {minScore}");
                        return new RecaptchaValidationResult 
                        { 
                            Success = false, 
                            Score = score,
                            ErrorMessage = $"reCAPTCHA score too low ({score:F2}). Please try again or refresh the page." 
                        };
                    }

                    return new RecaptchaValidationResult 
                    { 
                        Success = true, 
                        Score = score 
                    };
                }

                // reCAPTCHA v2 - just check success
                return new RecaptchaValidationResult 
                { 
                    Success = true 
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Network error during reCAPTCHA validation");
                return new RecaptchaValidationResult 
                { 
                    Success = false, 
                    ErrorMessage = "Network error while verifying reCAPTCHA. Please check your internet connection and try again." 
                };
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogError(ex, "reCAPTCHA validation timed out");
                return new RecaptchaValidationResult 
                { 
                    Success = false, 
                    ErrorMessage = "reCAPTCHA verification timed out. Please try again." 
                };
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse reCAPTCHA response");
                return new RecaptchaValidationResult 
                { 
                    Success = false, 
                    ErrorMessage = "Invalid reCAPTCHA response. Please refresh the page and try again." 
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during reCAPTCHA validation");
                return new RecaptchaValidationResult 
                { 
                    Success = false, 
                    ErrorMessage = "An error occurred during reCAPTCHA verification. Please try again." 
                };
            }
        }

        private string GetErrorMessage(List<string?> errorCodes)
        {
            if (errorCodes.Contains("missing-input-secret"))
                return "reCAPTCHA secret key is missing";
            if (errorCodes.Contains("invalid-input-secret"))
                return "reCAPTCHA secret key is invalid";
            if (errorCodes.Contains("missing-input-response"))
                return "reCAPTCHA response is missing";
            if (errorCodes.Contains("invalid-input-response"))
                return "reCAPTCHA response is invalid or expired";
            if (errorCodes.Contains("bad-request"))
                return "Bad request to reCAPTCHA API";
            if (errorCodes.Contains("timeout-or-duplicate"))
                return "reCAPTCHA timeout or duplicate token";
            if (errorCodes.Contains("browser-error"))
                return "Browser error - reCAPTCHA failed to load properly. Please refresh the page.";

            return string.Join(", ", errorCodes);
        }
    }

    public class RecaptchaValidationResult
    {
        public bool Success { get; set; }
        public double? Score { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
