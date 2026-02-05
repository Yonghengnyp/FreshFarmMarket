using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApp_Core_Identity.Model;
using FreshFarmMarket.Services;
using FreshFarmMarket.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Add HttpContextAccessor for accessing HTTP context in services
builder.Services.AddHttpContextAccessor();

// Configure AuthDbContext for MySQL (using market_reg database)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

// Configure ASP.NET Core Identity with your Member model
builder.Services.AddIdentity<Member, IdentityRole<int>>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;
    options.Password.RequiredUniqueChars = 4;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<int>("AccountPolicy:LockoutDurationMinutes", 15));
    options.Lockout.MaxFailedAccessAttempts = builder.Configuration.GetValue<int>("AccountPolicy:MaxFailedLoginAttempts", 3);
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;

    // Sign-in settings
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;

    // Tokens - Use custom 8-digit authenticator provider
    options.Tokens.AuthenticatorTokenProvider = "EightDigitAuthenticator";
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders() // Required for password reset, email confirmation, etc.
.AddTokenProvider<EightDigitTotpSecurityStampBasedTokenProvider<Member>>("EightDigitAuthenticator"); // Add 8-digit TOTP provider

// Configure application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<int>("AccountPolicy:SessionTimeoutMinutes", 30));
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Error/403";
    options.SlidingExpiration = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

// Register custom services
builder.Services.AddScoped<EncryptionService>();
builder.Services.AddScoped<PasswordValidationService>();
builder.Services.AddScoped<AuditLogService>();
builder.Services.AddScoped<RecaptchaService>();
builder.Services.AddScoped<IEmailService, EmailService>(); // Add email service

// Add HttpClient for reCAPTCHA and other HTTP calls
builder.Services.AddHttpClient();

// Configure session (still needed for some custom functionality)
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<int>("AccountPolicy:SessionTimeoutMinutes", 30));
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

// Configure antiforgery
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

var app = builder.Build();

// Initialize database - Auto create and migrate
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<Program>>();
    
    try
    {
        var context = services.GetRequiredService<AuthDbContext>();
        
        logger.LogInformation("?? Checking database connection...");
        
        // Check if we can connect
        var canConnect = await context.Database.CanConnectAsync();
        
        if (canConnect)
        {
            logger.LogInformation("? Connected to MySQL database");
            
            // Drop and recreate the database to ensure clean state
            logger.LogInformation("??? Dropping existing database...");
            await context.Database.EnsureDeletedAsync();
            
            logger.LogInformation("?? Creating database with Identity tables...");
            await context.Database.EnsureCreatedAsync();
            logger.LogInformation("? Database created successfully with all Identity tables!");
        }
        else
        {
            logger.LogWarning("?? Cannot connect to database, attempting to create...");
            await context.Database.EnsureCreatedAsync();
            logger.LogInformation("? Database created successfully!");
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "? An error occurred while initializing the database");
        logger.LogError($"Error: {ex.Message}");
        if (ex.InnerException != null)
        {
            logger.LogError($"Inner Error: {ex.InnerException.Message}");
        }
        logger.LogWarning("?? Application will continue, but database operations may fail");
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error/500");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

app.UseRouting();

// Add session middleware (before authentication)
app.UseSession();

// Authentication & Authorization (Identity middleware)
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
