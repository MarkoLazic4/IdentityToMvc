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
    // Second step of the login for accounts with two-factor authentication.
    public partial class AccountController
    {
        // ===========================================================================
        // GET: /User/Account/LoginWith2fa
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string? returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                // The 2FA cookie is missing or expired - start the login over
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            var viewModel = new LoginWith2faViewModel();
            viewModel.ReturnUrl = SanitizeReturnUrl(returnUrl);
            viewModel.RememberMe = rememberMe;

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/LoginWith2fa
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            if (!ModelState.IsValid)
            {
                return View(model);
            }


            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                // The 2FA cookie is missing or expired - start the login over
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
            }

            var authenticatorCode = model.Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            RecentAuthenticationService.FlagFreshSignIn(HttpContext);
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, model.RememberMe, model.Input.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.Id);
                return LocalRedirect(model.ReturnUrl);
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID '{UserId}' account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", user.Id);
                ModelState.AddModelError(string.Empty, _t["Invalid authenticator code."]);
                return View(model);
            }
        }

        // ===========================================================================
        // GET: /User/Account/LoginWithRecoveryCode
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> LoginWithRecoveryCode(string? returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                // The 2FA cookie is missing or expired - start the login over
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            var viewModel = new LoginWithRecoveryCodeViewModel();
            viewModel.ReturnUrl = SanitizeReturnUrl(returnUrl);

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/LoginWithRecoveryCode
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl);

            if (!ModelState.IsValid)
                return View(model);

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                // The 2FA cookie is missing or expired - start the login over
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
            }

            var recoveryCode = model.Input.RecoveryCode.Replace(" ", string.Empty);

            RecentAuthenticationService.FlagFreshSignIn(HttpContext);
            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with a recovery code.", user.Id);
                return LocalRedirect(model.ReturnUrl ?? DefaultUrl());
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
            }
            else
            {
                _logger.LogWarning("Invalid recovery code entered for user with ID '{UserId}' ", user.Id);
                ModelState.AddModelError(string.Empty, _t["Invalid recovery code entered."]);
                return View(model);
            }
        }
    }
}
