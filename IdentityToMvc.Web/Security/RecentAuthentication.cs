using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// "Sudo mode": remembers when the user last proved who they are (password, passkey, 2FA,
    /// external login). Sensitive account changes require that to have happened recently, so an
    /// unattended or stolen session can't be used to disable 2FA, change the email, etc.
    /// The marker is an encrypted, HttpOnly cookie bound to the user id and security stamp,
    /// so it dies with "sign out everywhere" and password changes.
    /// </summary>
    public sealed class RecentAuthenticationService
    {
        public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
        private const string CookieName = "__Host-IdentityToMvc.Reauth";

        private readonly ITimeLimitedDataProtector _protector;
        private readonly UserManager<IdentityUser> _userManager;

        public RecentAuthenticationService(IDataProtectionProvider provider, UserManager<IdentityUser> userManager)
        {
            _protector = provider.CreateProtector("IdentityToMvc.RecentAuthentication").ToTimeLimitedDataProtector();
            _userManager = userManager;
        }

        private const string FreshSignInItemKey = "fresh-sign-in";

        /// <summary>
        /// Call before a real sign-in (password, 2FA, recovery code, external login, passkey) so the
        /// new session starts in "recently authenticated" state. Session refreshes don't call it.
        /// </summary>
        public static void FlagFreshSignIn(HttpContext context) => context.Items[FreshSignInItemKey] = true;

        /// <summary>True when the current request is a real sign-in (not a session refresh).</summary>
        public static bool IsFreshSignIn(HttpContext context) => context.Items.ContainsKey(FreshSignInItemKey);

        /// <summary>Hooked up to the application cookie's OnSigningIn event.</summary>
        public void OnSigningIn(HttpContext context, System.Security.Claims.ClaimsPrincipal? principal)
        {
            if (principal == null || !context.Items.ContainsKey(FreshSignInItemKey))
                return;

            var userId = _userManager.GetUserId(principal);
            var stamp = principal.FindFirst(_userManager.Options.ClaimsIdentity.SecurityStampClaimType)?.Value;
            if (userId != null && stamp != null)
            {
                WriteCookie(context, userId, stamp);
            }
        }

        public async Task MarkAsync(HttpContext context, IdentityUser user)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user);
            WriteCookie(context, user.Id, stamp ?? string.Empty);
        }

        private void WriteCookie(HttpContext context, string userId, string stamp)
        {
            var payload = _protector.Protect($"{userId}|{stamp}", Window);
            context.Response.Cookies.Append(CookieName, payload, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = Window,
                IsEssential = true
            });
        }

        /// <summary>When the current "recently authenticated" window ends, or null if it isn't active.</summary>
        public async Task<DateTimeOffset?> GetExpirationAsync(HttpContext context, IdentityUser user)
        {
            if (!context.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
                return null;

            try
            {
                var payload = _protector.Unprotect(value, out var expiration);
                var stamp = await _userManager.GetSecurityStampAsync(user);
                return payload == $"{user.Id}|{stamp}" ? expiration : null;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return null;
            }
        }

        /// <summary>
        /// Re-issues the marker for the user's new security stamp, keeping the original expiry.
        /// </summary>
        public async Task RestoreAsync(HttpContext context, IdentityUser user, DateTimeOffset expiration)
        {
            var remaining = expiration - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
                return;

            var stamp = await _userManager.GetSecurityStampAsync(user);
            var payload = _protector.Protect($"{user.Id}|{stamp}", remaining);
            context.Response.Cookies.Append(CookieName, payload, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                MaxAge = remaining,
                IsEssential = true
            });
        }

        public async Task<bool> IsRecentAsync(HttpContext context, IdentityUser user)
        {
            if (!context.Request.Cookies.TryGetValue(CookieName, out var value) || string.IsNullOrEmpty(value))
                return false;

            try
            {
                var payload = _protector.Unprotect(value); // throws when expired or tampered with
                var stamp = await _userManager.GetSecurityStampAsync(user);
                return payload == $"{user.Id}|{stamp}";
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return false;
            }
        }

        public void Clear(HttpContext context) => context.Response.Cookies.Delete(CookieName, new CookieOptions { Path = "/", Secure = true });
    }

    /// <summary>
    /// Sends the user to "confirm your password" before the action runs unless they
    /// authenticated within <see cref="RecentAuthenticationService.Window"/>.
    /// Users without a local password (external login only) are not challenged.
    /// </summary>
    public sealed class RequireRecentAuthenticationAttribute : TypeFilterAttribute
    {
        public RequireRecentAuthenticationAttribute() : base(typeof(RequireRecentAuthenticationFilter)) { }

        private sealed class RequireRecentAuthenticationFilter : IAsyncActionFilter
        {
            private readonly UserManager<IdentityUser> _userManager;
            private readonly RecentAuthenticationService _recentAuthentication;

            public RequireRecentAuthenticationFilter(UserManager<IdentityUser> userManager, RecentAuthenticationService recentAuthentication)
            {
                _userManager = userManager;
                _recentAuthentication = recentAuthentication;
            }

#if (Sudo)
            /// <summary>Sends the user to "Confirm it's you" when the last authentication is too old.</summary>
            private async Task<bool> RedirectToConfirmIdentityAsync(ActionExecutingContext context)
            {
                var httpContext = context.HttpContext;
                var options = httpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<SecurityOptions>>().CurrentValue;
                var user = await _userManager.GetUserAsync(httpContext.User);
                if (!options.RequireRecentAuthentication
                    || user == null
                    || !await _userManager.HasPasswordAsync(user)
                    || await _recentAuthentication.IsRecentAsync(httpContext, user))
                {
                    return false;
                }

                // Come back to the page after confirming. For POSTs go back to the page the form was on.
                string? returnUrl = HttpMethods.IsGet(httpContext.Request.Method)
                    ? httpContext.Request.Path + httpContext.Request.QueryString
                    : LocalReferer(httpContext);

                context.Result = new RedirectToActionResult("ConfirmIdentity", "Manage", new { area = "User", returnUrl });
                return true;
            }

            private static string? LocalReferer(HttpContext context)
            {
                var referer = context.Request.Headers.Referer.ToString();
                if (Uri.TryCreate(referer, UriKind.Absolute, out var uri)
                    && string.Equals(uri.Host, context.Request.Host.Host, StringComparison.OrdinalIgnoreCase))
                {
                    return uri.PathAndQuery;
                }
                return null;
            }

#endif
            public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
            {
#if (Sudo)
                if (await RedirectToConfirmIdentityAsync(context))
                {
                    return;
                }
#endif
                await next();
            }
        }
    }
}
