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
    // Login and registration with external providers (Google, Facebook).
    public partial class AccountController
    {
        // ===========================================================================
        // POST: /User/Account/ExternalLogin
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string? returnUrl = null)
        {
            returnUrl = SanitizeReturnUrl(returnUrl);
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { area = "User", returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        // ===========================================================================
        // GET: /User/Account/ExternalLoginCallback
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
        {
            returnUrl = SanitizeReturnUrl(returnUrl) ?? DefaultUrl();

            if (remoteError != null)
            {
                TempData["ErrorMessage"] = _t["Error from external provider: {0}", remoteError].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                TempData["ErrorMessage"] = _t["Error loading external login information."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            // bypassTwoFactor: false - users who enabled 2FA must still enter their code
            RecentAuthenticationService.FlagFreshSignIn(HttpContext);
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity?.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
#if (TwoFactor)
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl, rememberMe = false });
            }
#endif
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
            }
            if (result.IsNotAllowed)
            {
                TempData["ErrorMessage"] = _t["You need to confirm your email before you can log in."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }
            else
            {
                // No account is linked to this provider login yet - offer to create one
                var providerEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
                if (string.IsNullOrWhiteSpace(providerEmail))
                {
                    TempData["ErrorMessage"] = _t["Your provider didn't share an email address. Sign up with your email first, then connect the provider under Manage account."].Value;
                    return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
                }

                var existing = await _userManager.FindByEmailAsync(providerEmail);
                if (existing != null && await _userManager.IsEmailConfirmedAsync(existing))
                {
                    // Never link automatically to an existing account: log in first, then connect
                    TempData["ErrorMessage"] = _t["An account with this email already exists. Log in with it, then connect the provider under Manage account."].Value;
                    return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
                }

                var viewModel = new ExternalLoginViewModel
                {
                    ReturnUrl = returnUrl,
                    ProviderDisplayName = info.ProviderDisplayName ?? info.LoginProvider,
                    Input = new ExternalLoginViewModel.InputModel { Email = providerEmail }
                };
                return View("ExternalLogin", viewModel);
            }
        }

        // ===========================================================================
        // POST: /User/Account/ExternalLoginConfirmation
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            // Get the information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                TempData["ErrorMessage"] = _t["Error loading external login information during confirmation."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
            }

            // The account email is always the one the provider verified - never what was typed in -
            // so an external login can't be used to claim someone else's address.
            var providerEmail = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrWhiteSpace(providerEmail))
            {
                TempData["ErrorMessage"] = _t["Your provider didn't share an email address. Sign up with your email first, then connect the provider under Manage account."].Value;
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
            }
            model.Input.Email = providerEmail;

            var existing = await _userManager.FindByEmailAsync(providerEmail);
            if (existing != null)
            {
                if (await _userManager.IsEmailConfirmedAsync(existing))
                {
                    TempData["ErrorMessage"] = _t["An account with this email already exists. Log in with it, then connect the provider under Manage account."].Value;
                    return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
                }
                // Unconfirmed account for an address the provider has verified: replace it
                await _userManager.DeleteAsync(existing);
            }

            var user = new IdentityUser
            {
                UserName = providerEmail,
                Email = providerEmail,
                // Google/Facebook only hand out addresses they have verified
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await _userManager.AddLoginAsync(user, info);
                if (!result.Succeeded)
                {
                    // Don't leave behind an account without any way to log in
                    await _userManager.DeleteAsync(user);
                }
                else
                {
                    _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
#if (Admin)
                    await _adminBootstrapper.EnsureAdminAsync(user);
#endif
                    RecentAuthenticationService.FlagFreshSignIn(HttpContext);
                    await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                    return LocalRedirect(model.ReturnUrl);
                }
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            model.ProviderDisplayName = info.ProviderDisplayName ?? info.LoginProvider;
            return View("ExternalLogin", model);
        }
    }
}
