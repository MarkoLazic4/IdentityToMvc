using IdentityToMvc.Web.Areas.User.ViewModels.Manage;
using IdentityToMvc.Web.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Shared;
using System.Text.Encodings.Web;

namespace IdentityToMvc.Web.Areas.User.Controllers
{
    [Area("User")]
    [Authorize]
    [Route("{area}/Account/[controller]/[action]")]
    public class ManageController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<ManageController> _logger;
        public ManageController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<ManageController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        // ===========================================================================
        // GET: /User/Account/Manage/EnableAuthenticator
        // ===========================================================================
        [HttpGet]
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
                ModelState.AddModelError("Input.Code", "Verification code is invalid.");
                (model.SharedKey, model.AuthenticatorUri) = await AuthenticatorHelper.LoadSharedKeyAndQrCodeUriAsync(_userManager, urlEncoder, user);
                return View();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

            model.StatusMessage = "Your authenticator app has been verified.";

            if (await _userManager.CountRecoveryCodesAsync(user) == 0)
            {
                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                model.RecoveryCodes = recoveryCodes?.ToArray();
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
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                throw new InvalidOperationException($"Cannot disable 2FA for user as it's not currently enabled.");
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/Disable2fa
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Disable2fa")]
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
                throw new InvalidOperationException($"Unexpected error occurred disabling 2FA.");
            }

            _logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", _userManager.GetUserId(User));
            TempData["StatusMessage"] = "2fa has been disabled. You can reenable 2fa when you setup an authenticator app";
            return RedirectToPage(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ResetAuthenticator
        // ===========================================================================
        [HttpGet]
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
            TempData["StatusMessage"] = "Your authenticator app key has been reset, you will need to configure your authenticator app using the new key.";

            return RedirectToAction(nameof(EnableAuthenticator), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/GenerateRecoveryCodes
        // ===========================================================================
        [HttpGet]
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
                throw new InvalidOperationException($"Cannot generate recovery codes for user because they do not have 2FA enabled.");
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/GenerateRecoveryCodes
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("GenerateRecoveryCodes")]
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
                throw new InvalidOperationException($"Cannot generate recovery codes for user as they do not have 2FA enabled.");
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData["RecoveryCodes"] = recoveryCodes?.ToArray();

            _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", userId);
            TempData["StatusMessage"] = "You have generated new recovery codes.";
            return RedirectToAction(nameof(ShowRecoveryCodes), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ShowRecoveryCodes
        // ===========================================================================
        [HttpGet]
        public IActionResult ShowRecoveryCodes()
        {
            if (!TempData.TryGetValue("RecoveryCodes", out var raw) || raw == null || string.IsNullOrWhiteSpace(raw.ToString()))
            {
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            return View();
        }

        // ===========================================================================
        // GET: /User/Account/Manage/TwoFactorAuthentication
        // ===========================================================================
        [HttpGet]
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
        public async Task<IActionResult> ForgetBrowser()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _signInManager.ForgetTwoFactorClientAsync();
            TempData["StatusMessage"] = "The current browser has been forgotten. When you login again from this browser you will be prompted for your 2fa code.";
            return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
        }
    }
}
