using System.Net;
using IdentityToMvc.Tests.Infrastructure;

namespace IdentityToMvc.Tests;

public class SiteTests : IClassFixture<TestAppFactory>
{
    private readonly TestAppFactory _factory;

    public SiteTests(TestAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Pages_carry_the_security_headers()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var csp = string.Join(";", response.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("'nonce-", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task Account_pages_are_not_cached()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.GetAsync("/User/Account/Login");

        Assert.True(response.Headers.CacheControl?.NoStore);
    }

#if (LangEn)
    [Fact]
    public async Task English_browsers_get_the_English_ui()
    {
        using var browser = _factory.CreateBrowser("en");
        var page = await browser.GetPageAsync("/User/Account/Login");

        Assert.Contains("Log in", page);
    }

#endif
#if (LangSr)
    [Theory]
    [InlineData("sr")]
    [InlineData("sr-Latn-RS")]
    [InlineData("hr")]
    public async Task Serbian_speaking_browsers_get_the_Serbian_ui(string language)
    {
        using var browser = _factory.CreateBrowser(language);
        var page = await browser.GetPageAsync("/User/Account/Login");

        Assert.Contains("Prijavi se", page);
    }

#endif
#if (LangBoth)
    [Fact]
    public async Task The_language_switch_is_remembered()
    {
        using var browser = _factory.CreateBrowser("en");
        var response = await browser.SubmitAsync("/", new Dictionary<string, string> { ["culture"] = "sr-Latn-RS" },
            "/Home/SetLanguage?returnUrl=%2FUser%2FAccount%2FLogin");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/User/Account/Login", response.Headers.Location!.OriginalString);
        Assert.Contains("Prijavi se", await browser.GetPageAsync("/User/Account/Login"));
    }

    [Fact]
    public async Task The_language_switch_does_not_redirect_to_other_sites()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.SubmitAsync("/", new Dictionary<string, string> { ["culture"] = "en" },
            "/Home/SetLanguage?returnUrl=https%3A%2F%2Fevil.example%2F");

        Assert.StartsWith("/", response.Headers.Location!.OriginalString);
    }

#endif
    [Fact]
    public async Task Missing_pages_show_a_friendly_404()
    {
        using var browser = _factory.CreateBrowser();
        var response = await browser.GetAsync("/this/does/not/exist");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("<html", await response.Content.ReadAsStringAsync());
    }
}
