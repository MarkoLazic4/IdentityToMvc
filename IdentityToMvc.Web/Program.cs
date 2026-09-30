using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Security;
using IdentityToMvc.Web.Services;
using IdentityToMvc.Web.Settings;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// appsettings.json, appsettings.{Environment}.json, user secrets (Development),
// environment variables and command-line args are already loaded by CreateBuilder.
// appsettings.Local.json is layered on top for local overrides; environment variables
// and command-line args are re-added so they keep the highest priority.
builder.Configuration
    .AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables()
    .AddCommandLine(args);

// Don't advertise the web server in the "Server" response header
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

builder.Services.Configure<SecurityOptions>(builder.Configuration.GetSection("Security"));

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"));
});

// ---------------------------------------------------------------------------
// Data Protection: keys protect auth cookies, antiforgery tokens and Identity
// tokens (email confirmation, password reset). Persist them in the database so
// they survive restarts/deployments and are shared by every app instance.
// ---------------------------------------------------------------------------
builder.Services.AddDataProtection()
    .SetApplicationName("IdentityToMvc")
    .PersistKeysToDbContext<ApplicationDbContext>();

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 4;

    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedAccount = true;
    options.SignIn.RequireConfirmedEmail = true;

    // Schema version 3 adds the passkey (WebAuthn) table
    options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddPasswordValidator<UserInfoPasswordValidator>()
.AddPasswordValidator<BreachedPasswordValidator>();

// Passkeys: require user verification (biometrics / device PIN) so a passkey is a real
// second factor on its own and can replace password + 2FA.
builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.UserVerificationRequirement = "required";
    options.ResidentKeyRequirement = "required";
    options.AuthenticatorTimeout = TimeSpan.FromMinutes(3);
    var serverDomain = builder.Configuration["Security:PasskeyServerDomain"];
    if (!string.IsNullOrWhiteSpace(serverDomain))
    {
        options.ServerDomain = serverDomain;
    }
});

// OWASP 2023 recommendation for PBKDF2-HMAC-SHA512 is 210,000 iterations; PBKDF2-HMAC-SHA256
// 600,000. Identity's V3 format uses HMAC-SHA512 - use 600,000 for extra margin. Existing hashes
// with fewer iterations are transparently re-hashed on the next successful login.
builder.Services.Configure<PasswordHasherOptions>(options => options.IterationCount = 600_000);

// Email confirmation / password reset / change email links expire after 3 hours (default: 1 day)
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
    options.TokenLifespan = TimeSpan.FromHours(3));

// Re-validate the security stamp often so "sign out everywhere", password changes and
// disabled accounts take effect on other devices within 5 minutes.
builder.Services.Configure<SecurityStampValidatorOptions>(options =>
    options.ValidationInterval = TimeSpan.FromMinutes(5));

// ---------------------------------------------------------------------------
// Cookies: the __Host- prefix makes the browser reject the cookie unless it is
// Secure, has Path=/ and no Domain - so a sibling subdomain can't overwrite it.
// ---------------------------------------------------------------------------
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "__Host-IdentityToMvc.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.Path = "/";
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    options.SlidingExpiration = true;

    // Start "sudo mode" when the user actually authenticates (see RecentAuthenticationService)
    options.Events.OnSigningIn = context =>
    {
        context.HttpContext.RequestServices.GetRequiredService<RecentAuthenticationService>()
            .OnSigningIn(context.HttpContext, context.Principal);
        return Task.CompletedTask;
    };

    options.LoginPath = "/User/Account/Login";
    options.LogoutPath = "/User/Account/Logout";
    options.AccessDeniedPath = "/User/Account/AccessDenied";
});

foreach (var scheme in new[] { IdentityConstants.ExternalScheme, IdentityConstants.TwoFactorUserIdScheme, IdentityConstants.TwoFactorRememberMeScheme })
{
    builder.Services.Configure<CookieAuthenticationOptions>(scheme, options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });
}

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__Host-IdentityToMvc.Xsrf";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.HeaderName = "X-XSRF-TOKEN";
});

builder.Services.Configure<CookieTempDataProviderOptions>(options =>
{
    options.Cookie.Name = "__Host-IdentityToMvc.TempData";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// External login providers are only added when their keys are configured, so the
// "Log in with ..." buttons never show up for a provider that can't work.
var authentication = builder.Services.AddAuthentication();
if (!string.IsNullOrWhiteSpace(builder.Configuration["GoogleClientId"]))
{
    authentication.AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["GoogleClientId"]!;
        options.ClientSecret = builder.Configuration["GoogleClientSecret"]!;
    });
}
if (!string.IsNullOrWhiteSpace(builder.Configuration["FacebookAppId"]))
{
    authentication.AddFacebook(options =>
    {
        options.AppId = builder.Configuration["FacebookAppId"]!;
        options.AppSecret = builder.Configuration["FacebookAppSecret"]!;
    });
}

// ---------------------------------------------------------------------------
// Email, notifications, breached password check, rate limiting
// ---------------------------------------------------------------------------
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SMTP"));
builder.Services.AddSingleton<IEmailService, EmailService>();
builder.Services.AddSingleton<EmailQueue>();
builder.Services.AddSingleton<IEmailQueue>(sp => sp.GetRequiredService<EmailQueue>());
builder.Services.AddHostedService<EmailQueueWorker>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ISecurityNotifier, SecurityNotifier>();
builder.Services.AddScoped<RecentAuthenticationService>();

builder.Services.AddHttpClient(BreachedPasswordValidator.HttpClientName, client =>
{
    client.BaseAddress = new Uri("https://api.pwnedpasswords.com/");
    client.Timeout = TimeSpan.FromSeconds(3);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("IdentityToMvc-PasswordCheck");
});

builder.Services.AddAccountRateLimiting();

// Behind a reverse proxy the client IP / scheme come from X-Forwarded-* headers. Only the
// proxies listed in "Security:KnownProxies" (plus loopback) are trusted to set them.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    foreach (var proxy in builder.Configuration.GetSection("Security:KnownProxies").Get<string[]>() ?? [])
    {
        if (System.Net.IPAddress.TryParse(proxy, out var address))
        {
            options.KnownProxies.Add(address);
        }
    }
});

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseStatusCodePagesWithReExecute("/Home/StatusCode", "?code={0}");

app.UseHttpsRedirection();
app.UseRouting();

if (builder.Configuration.GetValue("Security:EnableRateLimiting", true))
{
    app.UseRateLimiter();
}
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
