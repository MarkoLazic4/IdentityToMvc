using IdentityToMvc.Web.Areas.User.ViewModels.Manage;
using IdentityToMvc.Web.Helpers;
using IdentityToMvc.Web.Localization;
using IdentityToMvc.Web.Security;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Text.Json;
namespace IdentityToMvc.Web.Areas.User.Controllers
{
    // Two-factor authentication: authenticator app, recovery codes, remembered browsers.
    public partial class ManageController
    {
        // ===========================================================================
        // GET: /User/Account/Manage/EnableAuthenticator
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> EnableAuthenticator([FromServices] UrlEncoder urlEncoder)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var (sharedKey, authenticatorUri) = await AuthenticatorHelper.LoadSharedKeyAndQrCodeUriAsync(_userManager, urlEncoder, user);

            var viewModel = new EnableAuthenticatorViewModel();
            viewModel.SharedKey = sharedKey;
            viewModel.AuthenticatorUri = authenticatorUri;

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/EnableAuthenticator
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> EnableAuthenticator([FromServices] UrlEncoder urlEncoder, EnableAuthenticatorViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                (model.SharedKey, model.AuthenticatorUri) = await AuthenticatorHelper.LoadSharedKeyAndQrCodeUriAsync(_userManager, urlEncoder, user);
                return View(model);
            }

            // Strip spaces and hyphens
            var verificationCode = model.Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Input.Code", _t["Verification code is invalid."]);
                (model.SharedKey, model.AuthenticatorUri) = await AuthenticatorHelper.LoadSharedKeyAndQrCodeUriAsync(_userManager, urlEncoder, user);
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

            await _securityNotifier.NotifyAsync(user, SecurityEvent.TwoFactorEnabled);
            this.StatusSuccess(_t["Your authenticator app has been verified."]);

            if (await _userManager.CountRecoveryCodesAsync(user) == 0)
            {
                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                TempData["RecoveryCodes"] = recoveryCodes?.ToArray();
                return RedirectToAction(nameof(ShowRecoveryCodes), "Manage", new { area = "User" });
            }
            else
            {
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }
        }

        // ===========================================================================
        // GET: /User/Account/Manage/Disable2fa
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                this.StatusError(_t["Two-factor authentication is not enabled."]);
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/Disable2fa
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Disable2fa")]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> Disable2faPost()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                this.StatusError(_t["Unexpected error occurred disabling 2FA."]);
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            _logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", _userManager.GetUserId(User));
            await _securityNotifier.NotifyAsync(user, SecurityEvent.TwoFactorDisabled);
            this.StatusSuccess(_t["2fa has been disabled. You can reenable 2fa when you setup an authenticator app"]);
            return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ResetAuthenticator
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> ResetAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ResetAuthenticator
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("ResetAuthenticator")]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> ResetAuthenticatorKey()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has reset their authentication app key.", user.Id);

            await _signInManager.RefreshSignInAsync(user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.AuthenticatorReset);
            this.StatusSuccess(_t["Your authenticator app key has been reset, you will need to configure your authenticator app using the new key."]);

            return RedirectToAction(nameof(EnableAuthenticator), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/GenerateRecoveryCodes
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (!isTwoFactorEnabled)
            {
                this.StatusError(_t["Enable two-factor authentication before generating recovery codes."]);
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/GenerateRecoveryCodes
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("GenerateRecoveryCodes")]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> GenerateRecoveryCodesPost()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            if (!isTwoFactorEnabled)
            {
                this.StatusError(_t["Enable two-factor authentication before generating recovery codes."]);
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData["RecoveryCodes"] = recoveryCodes?.ToArray();

            _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", userId);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.RecoveryCodesGenerated);
            this.StatusSuccess(_t["You have generated new recovery codes."]);
            return RedirectToAction(nameof(ShowRecoveryCodes), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ShowRecoveryCodes
        // ===========================================================================
        [HttpGet]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public IActionResult ShowRecoveryCodes()
        {
            if (TempData["RecoveryCodes"] is not string[] recoveryCodes || recoveryCodes.Length == 0)
            {
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            return View(recoveryCodes);
        }

        // ===========================================================================
        // GET: /User/Account/Manage/TwoFactorAuthentication
        // ===========================================================================
        [HttpGet]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> TwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var viewModel = new TwoFactorAuthenticationViewModel();
            viewModel.HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null;
            viewModel.Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            viewModel.IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user);
            viewModel.RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user);

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ForgetBrowser
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [FeatureGate(SecurityFeature.TwoFactor)]
        public async Task<IActionResult> ForgetBrowser()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _signInManager.ForgetTwoFactorClientAsync();
            this.StatusSuccess(_t["The current browser has been forgotten. When you login again from this browser you will be prompted for your 2fa code."]);
            return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
        }
    }
}
