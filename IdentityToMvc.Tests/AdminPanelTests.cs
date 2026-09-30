using System.Net;
using IdentityToMvc.Tests.Infrastructure;
using IdentityToMvc.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityToMvc.Tests;

public class AdminPanelAccessTests : IClassFixture<TestAppFactory>
{
    private readonly TestAppFactory _factory;

    public AdminPanelAccessTests(TestAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Anonymous_visitors_are_sent_to_the_login_page()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.GetAsync("/Admin/Dashboard");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/User/Account/Login", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Regular_users_are_denied()
    {
        using var browser = _factory.CreateBrowser();
        await browser.CreateConfirmedUserAndLoginAsync($"plain-{Guid.NewGuid():N}@example.test");

        var response = await browser.GetAsync("/Admin/Users");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/User/Account/AccessDenied", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Admins_without_two_factor_must_set_it_up_first()
    {
        using var browser = _factory.CreateBrowser();
        await browser.CreateConfirmedUserAndLoginAsync(TestAppFactory.AdminEmail);

        var response = await browser.GetAsync("/Admin/Dashboard");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/User/Account/Manage/", response.Headers.Location!.OriginalString);
    }
}

public class AdminPanelTests : IClassFixture<AdminWithoutTwoFactorFactory>
{
    private readonly AdminWithoutTwoFactorFactory _factory;

    public AdminPanelTests(AdminWithoutTwoFactorFactory factory) => _factory = factory;

    private async Task<TestBrowser> AdminBrowserAsync()
    {
        var browser = _factory.CreateBrowser();
        using (var scope = _factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            if (await users.FindByEmailAsync(TestAppFactory.AdminEmail) != null)
            {
                Assert.Equal(HttpStatusCode.Redirect, (await browser.LoginAsync(TestAppFactory.AdminEmail)).StatusCode);
                return browser;
            }
        }
        await browser.CreateConfirmedUserAndLoginAsync(TestAppFactory.AdminEmail);
        return browser;
    }

    [Fact]
    public async Task Confirming_a_configured_admin_email_grants_the_admin_role()
    {
        using var admin = await AdminBrowserAsync();

        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var user = await users.FindByEmailAsync(TestAppFactory.AdminEmail);
        Assert.True(await users.IsInRoleAsync(user!, AdminBootstrapper.AdminRole));

        var dashboard = await admin.GetPageAsync("/Admin/Dashboard");
        Assert.Contains("Admin panel", dashboard);
    }

    [Fact]
    public async Task Admin_can_lock_a_user_and_the_user_is_signed_out()
    {
        var email = $"victim-{Guid.NewGuid():N}@example.test";
        using var user = _factory.CreateBrowser();
        await user.CreateConfirmedUserAndLoginAsync(email);

        using var admin = await AdminBrowserAsync();
        string userId;
        using (var scope = _factory.Services.CreateScope())
            userId = (await scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>().FindByEmailAsync(email))!.Id;

        var details = await admin.GetPageAsync($"/Admin/Users/Details/{userId}");
        Assert.Contains(email, details);
        var lockResult = await admin.PostAsync("/Admin/Users/Lock", new Dictionary<string, string> { ["id"] = userId },
            TestBrowser.AntiforgeryToken(details));
        Assert.Equal(HttpStatusCode.Redirect, lockResult.StatusCode);

        // The user's existing session ends and logging in again is refused
        var after = await user.GetAsync("/User/Account/Manage/Index");
        Assert.Equal(HttpStatusCode.Redirect, after.StatusCode);
        Assert.Contains("/User/Account/Login", after.Headers.Location!.OriginalString);
        var login = await user.LoginAsync(email);
        Assert.Contains("/Lockout", login.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Admin_cannot_lock_themselves_out()
    {
        using var admin = await AdminBrowserAsync();
        string adminId;
        using (var scope = _factory.Services.CreateScope())
            adminId = (await scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>().FindByEmailAsync(TestAppFactory.AdminEmail))!.Id;

        var details = await admin.GetPageAsync($"/Admin/Users/Details/{adminId}");
        await admin.PostAsync("/Admin/Users/Lock", new Dictionary<string, string> { ["id"] = adminId },
            TestBrowser.AntiforgeryToken(details));

        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/Admin/Dashboard")).StatusCode);
    }
}
