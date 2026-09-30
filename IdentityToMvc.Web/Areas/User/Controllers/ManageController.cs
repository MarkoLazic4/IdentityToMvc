using IdentityToMvc.Web.Areas.User.ViewModels.Manage;
using IdentityToMvc.Web.Helpers;
using IdentityToMvc.Web.Security;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace IdentityToMvc.Web.Areas.User.Controllers
{
    [Area("User")]
    [Authorize]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [TypeFilter(typeof(RefreshSessionOnSecurityStampChangeFilter))]
    [Route("{area}/Account/[controller]/[action]")]
    public class ManageController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISecurityNotifier _securityNotifier;
        private readonly RecentAuthenticationService _recentAuthentication;
        private readonly ILogger<ManageController> _logger;

        public ManageController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ISecurityNotifier securityNotifier, RecentAuthenticationService recentAuthentication, ILogger<ManageController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _securityNotifier = securityNotifier;
            _recentAuthentication = recentAuthentication;
            _logger = logger;
        }

        // ===========================================================================
        // GET: /User/Account/Manage/EnableAuthenticator
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
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
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

            await _securityNotifier.NotifyAsync(user, SecurityEvent.TwoFactorEnabled);
            TempData["StatusMessage"] = "Your authenticator app has been verified.";

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
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                TempData["StatusMessage"] = "Error: two-factor authentication is not enabled.";
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
                TempData["StatusMessage"] = "Error: unexpected error occurred disabling 2FA.";
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            _logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", _userManager.GetUserId(User));
            await _securityNotifier.NotifyAsync(user, SecurityEvent.TwoFactorDisabled);
            TempData["StatusMessage"] = "2fa has been disabled. You can reenable 2fa when you setup an authenticator app";
            return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ResetAuthenticator
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
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
            TempData["StatusMessage"] = "Your authenticator app key has been reset, you will need to configure your authenticator app using the new key.";

            return RedirectToAction(nameof(EnableAuthenticator), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/GenerateRecoveryCodes
        // ===========================================================================
        [HttpGet]
        [RequireRecentAuthentication]
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
                TempData["StatusMessage"] = "Error: enable two-factor authentication before generating recovery codes.";
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
                TempData["StatusMessage"] = "Error: enable two-factor authentication before generating recovery codes.";
                return RedirectToAction(nameof(TwoFactorAuthentication), "Manage", new { area = "User" });
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData["RecoveryCodes"] = recoveryCodes?.ToArray();

            _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", userId);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.RecoveryCodesGenerated);
            TempData["StatusMessage"] = "You have generated new recovery codes.";
            return RedirectToAction(nameof(ShowRecoveryCodes), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ShowRecoveryCodes
        // ===========================================================================
        [HttpGet]
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

        // ===========================================================================
        // GET: /User/Account/Manage/Index
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var viewModel = new IndexViewModel()
            { 
                Username = await _userManager.GetUserNameAsync(user) ?? string.Empty,
                Input = new IndexViewModel.InputModel
                {
                    PhoneNumber = await _userManager.GetPhoneNumberAsync(user)
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/Index
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(IndexViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model.Username = await _userManager.GetUserNameAsync(user) ?? string.Empty;
                model.Input = new IndexViewModel.InputModel
                {
                    PhoneNumber = await _userManager.GetPhoneNumberAsync(user)
                };
                return View(model);
            }

            var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
            if (model.Input.PhoneNumber != phoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.Input.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    TempData["StatusMessage"] = "Error: unexpected error when trying to set phone number.";
                    return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
                }
            }

            await _signInManager.RefreshSignInAsync(user);
            TempData["StatusMessage"] = "Your profile has been updated";
            return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ExternalLogins
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ExternalLogins()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var viewModel = new ExternalLoginsViewModel();

            viewModel.CurrentLogins = await _userManager.GetLoginsAsync(user);
            viewModel.OtherLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
                .Where(auth => viewModel.CurrentLogins.All(ul => auth.Name != ul.LoginProvider))
            .ToList();

            var hasPassword = await _userManager.HasPasswordAsync(user);

            viewModel.ShowRemoveButton = hasPassword || viewModel.CurrentLogins.Count > 1;
            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/RemoveExternalLogin
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> RemoveExternalLogin(string loginProvider, string providerKey)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // The Remove button is hidden in the UI in this case, but the endpoint must enforce it too:
            // a user without a password must keep at least one external login.
            var hasPassword = await _userManager.HasPasswordAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);
            if (!hasPassword && logins.Count <= 1)
            {
                TempData["StatusMessage"] = "Error: you can't remove your only login. Set a password first.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            var result = await _userManager.RemoveLoginAsync(user, loginProvider, providerKey);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error: the external login was not removed.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            await _signInManager.RefreshSignInAsync(user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.ExternalLoginRemoved);
            TempData["StatusMessage"] = "The external login was removed.";
            return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/LinkLogin
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> LinkLogin(string provider)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // Request a redirect to the external login provider to link a login for the current user
            var redirectUrl = Url.Action(nameof(LinkLoginCallback), "Manage", new { area = "User" });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));
            return new ChallengeResult(provider, properties);
        }

        // ===========================================================================
        // GET: /User/Account/Manage/LinkLoginCallback
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> LinkLoginCallback()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var info = await _signInManager.GetExternalLoginInfoAsync(userId);
            if (info == null)
            {
                TempData["StatusMessage"] = "Error: unexpected error occurred loading external login info.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            var result = await _userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error: the external login was not added. External logins can only be associated with one account.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            await _securityNotifier.NotifyAsync(user, SecurityEvent.ExternalLoginAdded);
            TempData["StatusMessage"] = "The external login was added.";
            return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/PersonalData
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> PersonalData()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/DownloadPersonalData
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> DownloadPersonalData()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            _logger.LogInformation("User with ID '{UserId}' asked for their personal data.", _userManager.GetUserId(User));

            // Only include personal data for download
            var personalData = new Dictionary<string, string>();
            var personalDataProps = typeof(IdentityUser).GetProperties().Where(
                            prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
            foreach (var p in personalDataProps)
            {
                personalData.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
            }

            var logins = await _userManager.GetLoginsAsync(user);
            foreach (var l in logins)
            {
                personalData.Add($"{l.LoginProvider} external login provider key", l.ProviderKey);
            }

            personalData.Add($"Authenticator Key", await _userManager.GetAuthenticatorKeyAsync(user) ?? string.Empty);

            return File(JsonSerializer.SerializeToUtf8Bytes(personalData, new JsonSerializerOptions { WriteIndented = true }),
                "application/json", "PersonalData.json");
        }

        // ===========================================================================
        // GET: /User/Account/Manage/DeletePersonalData
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> DeletePersonalData()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var viewModel = new DeletePersonalDataViewModel();

            viewModel.RequirePassword = await _userManager.HasPasswordAsync(user);
            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/DeletePersonalData
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeletePersonalData(DeletePersonalDataViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model.RequirePassword = await _userManager.HasPasswordAsync(user);
            if (model.RequirePassword)
            {
                // Count wrong passwords towards lockout so a stolen session can't be used to guess the password
                var check = await _signInManager.CheckPasswordSignInAsync(user, model.Input.Password, lockoutOnFailure: true);
                if (check.IsLockedOut)
                {
                    await _signInManager.SignOutAsync();
                    return RedirectToAction("Lockout", "Account", new { area = "User" });
                }
                if (!check.Succeeded)
                {
                    ModelState.AddModelError(string.Empty, "Incorrect password.");
                    return View(model);
                }
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Unexpected error occurred deleting your account.");
                return View(model);
            }

            await _signInManager.SignOutAsync();
            _recentAuthentication.Clear(HttpContext);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.AccountDeleted);

            _logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

            return RedirectToAction("Index", "Home", new { area = "" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ChangePassword
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                return RedirectToAction(nameof(SetPassword), "Manage", new { area = "User" });
            }

            var viewModel = new ChangePasswordViewModel();

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ChangePassword
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.Input.OldPassword, model.Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");
            await _recentAuthentication.MarkAsync(HttpContext, user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasswordChanged);
            TempData["StatusMessage"] = "Your password has been changed. Your other sessions will be signed out.";

            return RedirectToAction(nameof(ChangePassword), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/SetPassword
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> SetPassword()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);

            if (hasPassword)
            {
                return RedirectToAction(nameof(ChangePassword), "Manage", new { area = "User" });
            }

            var viewModel = new SetPasswordViewModel();

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/SetPassword
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Input.NewPassword);
            if (!addPasswordResult.Succeeded)
            {
                foreach (var error in addPasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);
            await _recentAuthentication.MarkAsync(HttpContext, user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasswordSet);
            TempData["StatusMessage"] = "Your password has been set.";

            return RedirectToAction(nameof(SetPassword), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/Email
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Email()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var email = await _userManager.GetEmailAsync(user);
            var viewModel = new ChangeEmailViewModel 
            { 
                Email = email,
                IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user),
                Input = new ChangeEmailViewModel.InputModel
                {
                    NewEmail = email ?? string.Empty
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ChangeEmail
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> ChangeEmail([FromServices] IEmailService emailService, ChangeEmailViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var email = await _userManager.GetEmailAsync(user);

            if (!ModelState.IsValid)
            {
                model.Email = email;
                model.IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
                model.Input.NewEmail = email ?? string.Empty;
                return View(nameof(Email), model);
            }

            if (!string.Equals(model.Input.NewEmail, email, StringComparison.OrdinalIgnoreCase))
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateChangeEmailTokenAsync(user, model.Input.NewEmail);
                code = TokenEncoder.Encode(code);
                var callbackUrl = Url.Action(nameof(ConfirmEmailChange), "Manage",
                    new { area = "User", userId = userId, email = model.Input.NewEmail, code = code },
                    protocol: Request.Scheme) ?? string.Empty;
                var sent = await emailService.SendEmailAsync(model.Input.NewEmail, "Confirm your new email", EmailTemplates.ConfirmEmailChange(callbackUrl));
                if (sent)
                {
                    // Warn the current address too, in case someone else is trying to take over the account
                    await _securityNotifier.NotifyAsync(user, SecurityEvent.EmailChangeRequested);
                }

                TempData["StatusMessage"] = sent
                    ? "Confirmation link to change email sent. Please check your email."
                    : "Error: the confirmation email could not be sent. Please try again later.";
                return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
            }

            TempData["StatusMessage"] = "Your email is unchanged.";
            return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/SendVerificationEmail
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationEmail([FromServices] IEmailService emailService)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // The "new email" field posted with this form is irrelevant here, so ModelState is not checked
            var email = await _userManager.GetEmailAsync(user);

            if (string.IsNullOrEmpty(email))
            {
                TempData["StatusMessage"] = "Error: your account has no email address.";
                return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
            }

            var userId = await _userManager.GetUserIdAsync(user);

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = TokenEncoder.Encode(code);
            var callbackUrl = Url.Action("ConfirmEmail", "Account",
                new { area = "User", userId = userId, code = code },
                protocol: Request.Scheme) ?? string.Empty;
            var sent = await emailService.SendEmailAsync(email, "Confirm your email", EmailTemplates.ConfirmAccount(callbackUrl));

            TempData["StatusMessage"] = sent
                ? "Verification email sent. Please check your email."
                : "Error: the verification email could not be sent. Please try again later.";
            return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ConfirmEmailChange
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ConfirmEmailChange(string? userId, string? email, string? code)
        {
            if (userId == null || email == null || code == null)
            {
                return RedirectToAction("Index", "Home", new { area = "" });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            // The link is only valid for the account it was sent from
            if (!string.Equals(_userManager.GetUserId(User), userId, StringComparison.Ordinal))
            {
                TempData["StatusMessage"] = "Error: log in with the account that requested the email change and open the link again.";
                return View();
            }

            if (!TokenEncoder.TryDecode(code, out var token))
            {
                TempData["StatusMessage"] = "Error: the confirmation link is invalid or has expired.";
                return View();
            }

            var oldEmail = await _userManager.GetEmailAsync(user);
            var result = await _userManager.ChangeEmailAsync(user, email, token);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error changing email. The link may have expired or the address is already in use.";
                return View();
            }

            // In our UI email and user name are one and the same, so when we update the email
            // we need to update the user name.
            var setUserNameResult = await _userManager.SetUserNameAsync(user, email);
            if (!setUserNameResult.Succeeded)
            {
                TempData["StatusMessage"] = "Error changing user name.";
                return View();
            }

            await _signInManager.RefreshSignInAsync(user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.EmailChanged, overrideEmail: oldEmail);
            TempData["StatusMessage"] = "Thank you for confirming your email change.";
            return View();
        }

        // ===========================================================================
        // POST: /User/Account/Manage/SignOutEverywhere
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignOutEverywhere()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // A new security stamp invalidates every existing auth and "remember this browser"
            // cookie at their next validation (see SecurityStampValidatorOptions).
            await _userManager.UpdateSecurityStampAsync(user);
            await _signInManager.ForgetTwoFactorClientAsync();
            // Keep this session alive with a cookie carrying the new stamp
            await _signInManager.RefreshSignInAsync(user);
            await _recentAuthentication.MarkAsync(HttpContext, user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.SignedOutEverywhere);

            TempData["StatusMessage"] = "All other sessions will be signed out within a few minutes.";
            return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ConfirmIdentity  ("sudo mode")
        // ===========================================================================
        [HttpGet]
        public IActionResult ConfirmIdentity(string? returnUrl = null)
        {
            return View(new ConfirmIdentityViewModel { ReturnUrl = returnUrl });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ConfirmIdentity
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmIdentity(ConfirmIdentityViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // Wrong passwords count towards lockout just like on the login page
            var check = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            if (check.IsLockedOut)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("Lockout", "Account", new { area = "User" });
            }
            if (!check.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Incorrect password.");
                return View(model);
            }

            await _recentAuthentication.MarkAsync(HttpContext, user);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return LocalRedirect(model.ReturnUrl);
            }
            return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/Passkeys
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Passkeys([FromServices] IOptionsMonitor<SecurityOptions> securityOptions)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var passkeys = await _userManager.GetPasskeysAsync(user);
            var viewModel = new PasskeysViewModel
            {
                MaxPasskeys = securityOptions.CurrentValue.MaxPasskeysPerUser,
                Passkeys = passkeys
                    .OrderBy(p => p.CreatedAt)
                    .Select(p => new PasskeysViewModel.PasskeyItem
                    {
                        Id = WebEncoders.Base64UrlEncode(p.CredentialId),
                        Name = string.IsNullOrWhiteSpace(p.Name) ? "Unnamed passkey" : p.Name,
                        CreatedAt = p.CreatedAt,
                        IsBackedUp = p.IsBackedUp
                    })
                    .ToList()
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/PasskeyCreationOptions  (called from JavaScript)
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> PasskeyCreationOptions()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var userName = await _userManager.GetUserNameAsync(user) ?? "User";
            var optionsJson = await _signInManager.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
            {
                Id = await _userManager.GetUserIdAsync(user),
                Name = userName,
                DisplayName = userName
            });
            return Content(optionsJson, "application/json");
        }

        // ===========================================================================
        // POST: /User/Account/Manage/AddPasskey
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> AddPasskey([FromServices] IOptionsMonitor<SecurityOptions> securityOptions,
            string? credentialJson, string? name)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (string.IsNullOrWhiteSpace(credentialJson))
            {
                TempData["StatusMessage"] = "Error: the passkey registration was cancelled.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var existing = await _userManager.GetPasskeysAsync(user);
            if (existing.Count >= securityOptions.CurrentValue.MaxPasskeysPerUser)
            {
                TempData["StatusMessage"] = $"Error: you can register at most {securityOptions.CurrentValue.MaxPasskeysPerUser} passkeys.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var attestation = await _signInManager.PerformPasskeyAttestationAsync(credentialJson);
            if (!attestation.Succeeded)
            {
                _logger.LogWarning("Passkey attestation failed for user {UserId}: {Error}", user.Id, attestation.Failure?.Message);
                TempData["StatusMessage"] = "Error: the passkey could not be verified. Please try again.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var passkey = attestation.Passkey;
            passkey.Name = string.IsNullOrWhiteSpace(name) ? "Passkey" : name.Trim()[..Math.Min(name.Trim().Length, 50)];
            var result = await _userManager.AddOrUpdatePasskeyAsync(user, passkey);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error: the passkey could not be saved.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasskeyAdded);
            TempData["StatusMessage"] = $"Passkey \"{passkey.Name}\" was added. You can now use it to log in.";
            return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/RemovePasskey
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> RemovePasskey(string id)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            byte[] credentialId;
            try
            {
                credentialId = WebEncoders.Base64UrlDecode(id ?? string.Empty);
            }
            catch (FormatException)
            {
                return BadRequest();
            }

            // Never remove the last way to log in
            var hasPassword = await _userManager.HasPasswordAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);
            var passkeys = await _userManager.GetPasskeysAsync(user);
            if (!hasPassword && logins.Count == 0 && passkeys.Count <= 1)
            {
                TempData["StatusMessage"] = "Error: you can't remove your only way to log in. Set a password first.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var result = await _userManager.RemovePasskeyAsync(user, credentialId);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error: the passkey was not found.";
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasskeyRemoved);
            TempData["StatusMessage"] = "The passkey was removed.";
            return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
        }
    }
}
