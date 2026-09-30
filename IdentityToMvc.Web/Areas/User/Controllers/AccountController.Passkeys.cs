using IdentityToMvc.Web.Areas.User.ViewModels.Account;
using IdentityToMvc.Web.Helpers;
using IdentityToMvc.Web.Localization;
using IdentityToMvc.Web.Security;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Localization;
using System.Security.Claims;
namespace IdentityToMvc.Web.Areas.User.Controllers
{
    // Login with a passkey (WebAuthn).
    public partial class AccountController
    {
        // ===========================================================================
        // POST: /User/Account/PasskeyRequestOptions  (called from JavaScript)
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [DisableRateLimiting] // requested automatically on every login page view for passkey autofill
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> PasskeyRequestOptions()
        {
            // No user: the browser offers every discoverable passkey it has for this site
            var optionsJson = await _signInManager.MakePasskeyRequestOptionsAsync(user: null);
            return Content(optionsJson, "application/json");
        }

        // ===========================================================================
        // POST: /User/Account/LoginWithPasskey
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> LoginWithPasskey(string? credentialJson, string? returnUrl = null)
        {
            returnUrl = SanitizeReturnUrl(returnUrl) ?? DefaultUrl();

            if (string.IsNullOrWhiteSpace(credentialJson))
            {
                TempData["ErrorMessage"] = _t["The passkey sign-in was cancelled."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            var assertion = await _signInManager.PerformPasskeyAssertionAsync(credentialJson);
            if (!assertion.Succeeded)
            {
                _logger.LogWarning("Passkey assertion failed: {Error}", assertion.Failure?.Message);
                TempData["ErrorMessage"] = _t["This passkey couldn't be used to log in. It may have been removed from your account."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            var user = assertion.User;
            // Store the updated signature counter (detects cloned authenticators)
            await _userManager.AddOrUpdatePasskeyAsync(user, assertion.Passkey);

            if (!await _signInManager.CanSignInAsync(user))
            {
                TempData["ErrorMessage"] = _t["You need to confirm your email before you can log in."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                if (IsLockedByAdministrator(await _userManager.GetLockoutEndDateAsync(user)))
                {
                    return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
                }
                // A lockout from failed password attempts protects against guessing. A passkey can't be
                // guessed, so it still works - an attacker can't lock the owner out of their account.
                await _userManager.SetLockoutEndDateAsync(user, null);
            }
            await _userManager.ResetAccessFailedCountAsync(user);

            RecentAuthenticationService.FlagFreshSignIn(HttpContext);
            await _signInManager.SignInWithClaimsAsync(user, isPersistent: false, [new Claim("amr", "pop")]);
            _logger.LogInformation("User logged in with a passkey.");
            return LocalRedirect(returnUrl);
        }
    }
}
