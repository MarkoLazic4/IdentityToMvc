using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Administrators can take over any account, so their own account must be protected by more than
    /// a password: two-factor authentication or a passkey is required before the admin panel opens
    /// ("Security:RequireTwoFactorForAdmins", default true).
    /// </summary>
    public sealed class RequireAdminSecurityAttribute : TypeFilterAttribute
    {
        public RequireAdminSecurityAttribute() : base(typeof(Filter)) { }

        private sealed class Filter : IAsyncActionFilter
        {
            private readonly UserManager<IdentityUser> _userManager;
            private readonly IOptionsMonitor<SecurityOptions> _options;
            private readonly IConfiguration _configuration;
            private readonly IStringLocalizer<SharedResource> _t;

            public Filter(UserManager<IdentityUser> userManager, IOptionsMonitor<SecurityOptions> options,
                IConfiguration configuration, IStringLocalizer<SharedResource> localizer)
            {
                _userManager = userManager;
                _options = options;
                _configuration = configuration;
                _t = localizer;
            }

            public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
            {
                var options = _options.CurrentValue;
#if (TwoFactor && Passkeys)
                var available = options.EnableTwoFactor || options.EnablePasskeys;
                var setupPage = options.EnableTwoFactor ? "TwoFactorAuthentication" : "Passkeys";
#elif (TwoFactor)
                var available = options.EnableTwoFactor;
                var setupPage = "TwoFactorAuthentication";
#else
                var available = options.EnablePasskeys;
                var setupPage = "Passkeys";
#endif
                var required = _configuration.GetValue("Security:RequireTwoFactorForAdmins", true) && available;
                var user = await _userManager.GetUserAsync(context.HttpContext.User);

                if (required && user != null
                    && !await _userManager.GetTwoFactorEnabledAsync(user)
                    && (await _userManager.GetPasskeysAsync(user)).Count == 0)
                {
                    if (context.Controller is Controller controller)
                    {
                        controller.TempData[Localization.StatusMessageExtensions.MessageKey] =
                            _t["Administrators must turn on two-factor authentication or add a passkey before using the admin panel."].Value;
                        controller.TempData[Localization.StatusMessageExtensions.IsErrorKey] = true;
                    }
                    context.Result = new RedirectToActionResult(setupPage, "Manage", new { area = "User" });
                    return;
                }

                await next();
            }
        }
    }
}
