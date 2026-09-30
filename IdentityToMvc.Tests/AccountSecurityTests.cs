using System.Net;
using IdentityToMvc.Tests.Infrastructure;
using IdentityToMvc.Web.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityToMvc.Tests;

public class AccountSecurityTests : IClassFixture<TestAppFactory>
{
    private readonly TestAppFactory _factory;

    public AccountSecurityTests(TestAppFactory factory) => _factory = factory;

    private static string NewEmail() => $"user-{Guid.NewGuid():N}@example.test";

    [Fact]
    public async Task Register_confirm_and_login_works()
    {
        using var browser = _factory.CreateBrowser();
        var email = NewEmail();

        await browser.CreateConfirmedUserAndLoginAsync(email);

        var manage = await browser.GetAsync("/User/Account/Manage/Index");
        Assert.Equal(HttpStatusCode.OK, manage.StatusCode);
    }

    [Fact]
    public async Task Login_is_refused_until_the_email_is_confirmed()
    {
        using var browser = _factory.CreateBrowser();
        var email = NewEmail();
        await browser.RegisterAsync(email);

        var login = await browser.LoginAsync(email);

        Assert.Equal(HttpStatusCode.OK, login.StatusCode); // the form again, with an error
        Assert.Contains("Invalid login attempt", await login.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Registering_a_taken_email_looks_like_success_and_warns_the_owner()
    {
        using var owner = _factory.CreateBrowser();
        var email = NewEmail();
        await owner.CreateConfirmedUserAndLoginAsync(email);
        var received = _factory.Mailbox.For(email).Count;

        using var attacker = _factory.CreateBrowser();
        var response = await attacker.RegisterAsync(email, "Other-Secret-99!");

        // Same answer as a brand-new registration: nothing reveals that the address is taken
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("RegisterConfirmation", response.Headers.Location!.OriginalString);

        var warning = await _factory.Mailbox.WaitForAsync(email, received);
        Assert.Equal("You already have an account", warning.Subject);

        // The owner's password still works, the attacker's does not
        using var check = _factory.CreateBrowser();
        Assert.Equal(HttpStatusCode.OK, (await check.LoginAsync(email, "Other-Secret-99!")).StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, (await check.LoginAsync(email)).StatusCode);
    }

    [Fact]
    public async Task An_unconfirmed_registration_cannot_reserve_someone_elses_email()
    {
        var email = NewEmail();

        // Attacker registers the victim's address first and never confirms it
        using var attacker = _factory.CreateBrowser();
        await attacker.RegisterAsync(email, "Attacker-Pass-77!");

        // The real owner registers and confirms: the attacker's account is replaced
        using var victim = _factory.CreateBrowser();
        await victim.CreateConfirmedUserAndLoginAsync(email);

        using var check = _factory.CreateBrowser();
        var attackerLogin = await check.LoginAsync(email, "Attacker-Pass-77!");
        Assert.Equal(HttpStatusCode.OK, attackerLogin.StatusCode);
        Assert.Contains("Invalid login attempt", await attackerLogin.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Three_wrong_passwords_lock_the_account_and_email_an_unlock_link()
    {
        using var browser = _factory.CreateBrowser();
        var email = NewEmail();
        await browser.CreateConfirmedUserAndLoginAsync(email);
        var received = _factory.Mailbox.For(email).Count;

        using var attacker = _factory.CreateBrowser();
        HttpResponseMessage last = null!;
        for (var i = 0; i < 3; i++)
            last = await attacker.LoginAsync(email, "Wrong-Password-1!");

        Assert.Equal(HttpStatusCode.Redirect, last.StatusCode);
        Assert.Contains("/Lockout", last.Headers.Location!.OriginalString);

        // Even the right password is refused now
        var locked = await attacker.LoginAsync(email);
        Assert.Contains("/Lockout", locked.Headers.Location!.OriginalString);

        // The owner gets a link that lifts the lock
        var unlockEmail = await _factory.Mailbox.WaitForAsync(email, received, e => e.Subject == "Your account was locked");
        using var owner = _factory.CreateBrowser();
        await owner.GetAsync(unlockEmail.Link("/Unlock"));

        var login = await owner.LoginAsync(email);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.DoesNotContain("/Lockout", login.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Login_attempts_are_recorded_in_the_security_activity()
    {
        using var browser = _factory.CreateBrowser();
        var email = NewEmail();
        await browser.CreateConfirmedUserAndLoginAsync(email);

        using var other = _factory.CreateBrowser();
        await other.LoginAsync(email, "Wrong-Password-1!");

        using var scope = _factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var user = await users.FindByEmailAsync(email);
        var events = await db.SecurityEvents.Where(e => e.UserId == user!.Id).Select(e => e.Event).ToListAsync();

        Assert.Contains("SignedIn", events);
        Assert.Contains("LoginFailed", events);

        var activity = await browser.GetPageAsync("/User/Account/Manage/Activity");
        Assert.Contains("Failed login attempt", activity);
    }

    [Fact]
    public async Task Signing_out_everywhere_ends_the_other_sessions()
    {
        var email = NewEmail();
        using var laptop = _factory.CreateBrowser();
        await laptop.CreateConfirmedUserAndLoginAsync(email);

        using var phone = _factory.CreateBrowser();
        Assert.Equal(HttpStatusCode.Redirect, (await phone.LoginAsync(email)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await phone.GetAsync("/User/Account/Manage/Index")).StatusCode);

        var devices = await laptop.GetPageAsync("/User/Account/Manage/Devices");
        var result = await laptop.PostAsync("/User/Account/Manage/SignOutEverywhere", new Dictionary<string, string>(),
            TestBrowser.AntiforgeryToken(devices));
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);

        // The phone is sent back to the login page, the laptop stays signed in
        var phoneAfter = await phone.GetAsync("/User/Account/Manage/Index");
        Assert.Equal(HttpStatusCode.Redirect, phoneAfter.StatusCode);
        Assert.Contains("/User/Account/Login", phoneAfter.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync("/User/Account/Manage/Index")).StatusCode);
    }

    [Fact]
    public async Task Forms_without_an_antiforgery_token_are_rejected()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.Client.PostAsync("/User/Account/Login", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["Input.Email"] = "x@example.test", ["Input.Password"] = "whatever" }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("https://evil.example/")]
    [InlineData("//evil.example/")]
    public async Task Login_never_redirects_to_another_site(string returnUrl)
    {
        using var browser = _factory.CreateBrowser();
        var email = NewEmail();
        await browser.CreateConfirmedUserAndLoginAsync(email);

        using var other = _factory.CreateBrowser();
        var response = await other.SubmitAsync("/User/Account/Login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = TestBrowser.StrongPassword,
            ["ReturnUrl"] = returnUrl
        });

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/", response.Headers.Location!.OriginalString);
        Assert.DoesNotContain("evil.example", response.Headers.Location!.OriginalString);
    }
}
