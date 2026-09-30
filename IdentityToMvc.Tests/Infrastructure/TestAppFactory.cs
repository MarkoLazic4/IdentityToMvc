using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityToMvc.Tests.Infrastructure;

/// <summary>
/// Runs the real application in memory, with an in-memory SQLite database instead of SQL Server
/// and a fake mailbox instead of SMTP. Everything else (Identity, cookies, filters, headers,
/// localization) is the production configuration.
/// </summary>
public class TestAppFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@example.test";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public FakeMailbox Mailbox { get; } = new();

    protected virtual IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        ["ConnectionStrings:Default"] = "not-used",
        ["Security:CheckBreachedPasswords"] = "false",
        ["Security:EnableRateLimiting"] = "false",
        ["Admin:Emails:0"] = AdminEmail,
        ["Localization:DefaultCulture"] = "en",
        ["Logging:LogLevel:Default"] = "Warning"
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        _connection.Open();
        builder.UseEnvironment("Testing");
        foreach (var (key, value) in Settings)
            builder.UseSetting(key, value);

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<ApplicationDbContext>>();
            services.RemoveAll<DbContextOptions>();
            services.RemoveAll<IDbContextOptionsConfiguration<ApplicationDbContext>>();
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite(_connection));

            // Create the schema now, before startup code (admin role, Data Protection keys) touches the database.
            // A throw-away provider built from the app's own registrations gives the full Identity model (passkeys etc.).
            using (var provider = services.BuildServiceProvider())
            using (var scope = provider.CreateScope())
                scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.EnsureCreated();

            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService>(Mailbox);
        });
    }

    /// <summary>A browser-like client: HTTPS (needed for the __Host- cookies), cookies on, no auto-redirects.</summary>
    public TestBrowser CreateBrowser(string language = "en")
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(language);
        return new TestBrowser(client, this);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _connection.Dispose();
    }
}

/// <summary>Same app, but admins may open the admin panel without two-factor authentication.</summary>
public class AdminWithoutTwoFactorFactory : TestAppFactory
{
    protected override IDictionary<string, string?> Settings
    {
        get
        {
            var settings = base.Settings;
            settings["Security:RequireTwoFactorForAdmins"] = "false";
            return settings;
        }
    }
}

internal static class ServiceCollectionExtensions
{
    public static void RemoveAll<T>(this IServiceCollection services)
    {
        foreach (var descriptor in services.Where(d => d.ServiceType == typeof(T)).ToList())
            services.Remove(descriptor);
    }
}
