using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Rejects passwords that appear in known data breaches using the Have I Been Pwned
    /// "Pwned Passwords" range API. Only the first 5 characters of the SHA-1 hash leave the
    /// server (k-anonymity), and padding is requested so response sizes don't leak anything.
    /// If the API can't be reached the check fails open so users are never locked out of
    /// registering or changing their password.
    /// </summary>
    public sealed class BreachedPasswordValidator : IPasswordValidator<IdentityUser>
    {
        public const string HttpClientName = "pwned-passwords";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IOptionsMonitor<SecurityOptions> _options;
        private readonly ILogger<BreachedPasswordValidator> _logger;
        private readonly IStringLocalizer<SharedResource> _t;

        public BreachedPasswordValidator(IHttpClientFactory httpClientFactory, IOptionsMonitor<SecurityOptions> options,
            ILogger<BreachedPasswordValidator> logger, IStringLocalizer<SharedResource> localizer)
        {
            _t = localizer;
            _httpClientFactory = httpClientFactory;
            _options = options;
            _logger = logger;
        }

        public async Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user, string? password)
        {
            if (!_options.CurrentValue.CheckBreachedPasswords || string.IsNullOrEmpty(password))
                return IdentityResult.Success;

            var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
            var prefix = hash[..5];
            var suffix = hash[5..];

            try
            {
                var client = _httpClientFactory.CreateClient(HttpClientName);
                using var request = new HttpRequestMessage(HttpMethod.Get, $"range/{prefix}");
                request.Headers.Add("Add-Padding", "true");
                using var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var body = await response.Content.ReadAsStringAsync();
                foreach (var line in body.Split('\n'))
                {
                    var parts = line.Trim().Split(':');
                    if (parts.Length == 2
                        && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase)
                        && int.TryParse(parts[1], out var count) && count > 0)
                    {
                        return IdentityResult.Failed(new IdentityError
                        {
                            Code = "PasswordBreached",
                            Description = _t["This password has appeared in a data breach and can't be used. Please choose a different one."]
                        });
                    }
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                _logger.LogWarning(ex, "Breached password check skipped: the Pwned Passwords API could not be reached.");
            }

            return IdentityResult.Success;
        }
    }
}
