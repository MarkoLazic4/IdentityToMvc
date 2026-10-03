using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Many account changes rotate the security stamp (generating an authenticator key, enabling or
    /// disabling 2FA, changing the phone number or password, adding/removing logins...). That is what
    /// signs out the user's *other* sessions - but without a refresh the current session is signed
    /// out too at the next stamp validation. After any action that changed the stamp, this filter
    /// re-issues the current session's cookie (and the "recently authenticated" marker, keeping its
    /// original expiry) so only the other sessions are affected.
    /// </summary>
    public sealed class RefreshSessionOnSecurityStampChangeFilter : IAsyncActionFilter
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RecentAuthenticationService _recentAuthentication;

        public RefreshSessionOnSecurityStampChangeFilter(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager, RecentAuthenticationService recentAuthentication)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _recentAuthentication = recentAuthentication;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var httpContext = context.HttpContext;
            var userId = _userManager.GetUserId(httpContext.User);
            var user = userId == null ? null : await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                await next();
                return;
            }

            var stampBefore = await _userManager.GetSecurityStampAsync(user);
            var sudoExpiration = await _recentAuthentication.GetExpirationAsync(httpContext, user);

            var executed = await next();
            if (executed.Exception != null && !executed.ExceptionHandled)
                return;

            // Reload: the action may have deleted the user or locked the account
            var current = await _userManager.FindByIdAsync(userId!);
            if (current == null
                || await _userManager.IsLockedOutAsync(current)
                || await _userManager.GetSecurityStampAsync(current) == stampBefore)
            {
                return;
            }

            await _signInManager.RefreshSignInAsync(current);
            if (sudoExpiration.HasValue)
            {
                await _recentAuthentication.RestoreAsync(httpContext, current, sudoExpiration.Value);
            }
        }
    }
}
