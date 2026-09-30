using System.Net;
using System.Text.RegularExpressions;

namespace IdentityToMvc.Tests.Infrastructure;

/// <summary>
/// Minimal "browser" over HttpClient: keeps cookies, reads the antiforgery token from the page
/// it just loaded and submits forms with it, like a real user would.
/// </summary>
public sealed class TestBrowser : IDisposable
{
    public const string StrongPassword = "Blue-Kettle-42!";

    private readonly HttpClient _client;
    private readonly TestAppFactory _factory;

    public TestBrowser(HttpClient client, TestAppFactory factory)
    {
        _client = client;
        _factory = factory;
    }

    public HttpClient Client => _client;

    public Task<HttpResponseMessage> GetAsync(string url) => _client.GetAsync(url);

    public async Task<string> GetPageAsync(string url)
    {
        var response = await _client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>Loads <paramref name="pageUrl"/>, then posts <paramref name="fields"/> with its antiforgery token.</summary>
    public async Task<HttpResponseMessage> SubmitAsync(string pageUrl, IDictionary<string, string> fields, string? postUrl = null)
    {
        var page = await GetPageAsync(pageUrl);
        return await PostAsync(postUrl ?? pageUrl, fields, AntiforgeryToken(page));
    }

    public Task<HttpResponseMessage> PostAsync(string url, IDictionary<string, string> fields, string token)
    {
        var form = new Dictionary<string, string>(fields) { ["__RequestVerificationToken"] = token };
        return _client.PostAsync(url, new FormUrlEncodedContent(form));
    }

    public static string AntiforgeryToken(string html)
    {
        var match = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"");
        Assert.True(match.Success, "The page has no antiforgery token.");
        return match.Groups[1].Value;
    }

    // ---------- common flows ----------

    public Task<HttpResponseMessage> RegisterAsync(string email, string password = StrongPassword) =>
        SubmitAsync("/User/Account/Register", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
            ["Input.ConfirmPassword"] = password
        });

    public Task<HttpResponseMessage> LoginAsync(string email, string password = StrongPassword) =>
        SubmitAsync("/User/Account/Login", new Dictionary<string, string>
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password
        });

    /// <summary>Registers, clicks the confirmation link from the email and logs in.</summary>
    public async Task CreateConfirmedUserAndLoginAsync(string email, string password = StrongPassword)
    {
        var received = _factory.Mailbox.For(email).Count;
        var register = await RegisterAsync(email, password);
        Assert.Equal(HttpStatusCode.Redirect, register.StatusCode);

        var confirmation = await _factory.Mailbox.WaitForAsync(email, received);
        var confirm = await _client.GetAsync(confirmation.Link("/ConfirmEmail"));
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);

        var login = await LoginAsync(email, password);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.DoesNotContain("/Login", login.Headers.Location!.OriginalString);
    }

    public void Dispose() => _client.Dispose();
}
