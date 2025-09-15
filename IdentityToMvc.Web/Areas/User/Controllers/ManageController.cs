using IdentityToMvc.Web.Areas.User.ViewModels.Account;
using IdentityToMvc.Web.Areas.User.ViewModels.Manage;
using IdentityToMvc.Web.Helpers;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Shared;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

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
        [AutoValidateAntiforgeryToken]
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
                    model.StatusMessage = "Unexpected error when trying to set phone number.";
                    return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
                }
            }

            await _signInManager.RefreshSignInAsync(user);
            model.StatusMessage = "Your profile has been updated";
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
        public async Task<IActionResult> RemoveExternalLogin(string loginProvider, string providerKey)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var result = await _userManager.RemoveLoginAsync(user, loginProvider, providerKey);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "The external login was not removed.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            await _signInManager.RefreshSignInAsync(user);
            TempData["StatusMessage"] = "The external login was removed.";
            return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/LinkLogin
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
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
        // GET: /User/Profile/LinkLoginCallback
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
                throw new InvalidOperationException($"Unexpected error occurred loading external login info.");
            }

            var result = await _userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "The external login was not added. External logins can only be associated with one account.";
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

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
        [AutoValidateAntiforgeryToken]
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

            Response.Headers.TryAdd("Content-Disposition", "attachment; filename=PersonalData.json");
            return new FileContentResult(JsonSerializer.SerializeToUtf8Bytes(personalData), "application/json");
        }

        // ===========================================================================
        // GET: /User/Manage/Account/DeletePersonalData
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
        // POST: /User/Manage/Account/DeletePersonalData
        // ===========================================================================
        [HttpPost]
        [AutoValidateAntiforgeryToken]
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
                if (!await _userManager.CheckPasswordAsync(user, model.Input.Password))
                {
                    ModelState.AddModelError(string.Empty, "Incorrect password.");
                    return View(model);
                }
            }

            var result = await _userManager.DeleteAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Unexpected error occurred deleting user.");
            }

            await _signInManager.SignOutAsync();

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
            model.StatusMessage = "Your password has been changed.";

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
            model.StatusMessage = "Your password has been set.";

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
                return View(model);
            }

            if (model.Input.NewEmail != email)
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateChangeEmailTokenAsync(user, model.Input.NewEmail);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Action(nameof(ConfirmEmailChange), "Manage",
                    new { area = "User", userId = userId, email = model.Input.NewEmail, code = code },
                    protocol: Request.Scheme) ?? string.Empty;
                await emailService.SendEmailAsync("identitytomvc@gmail.com", model.Input.NewEmail, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                model.StatusMessage = "Confirmation link to change email sent. Please check your email.";
                return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
            }

            model.StatusMessage = "Your email is unchanged.";
            return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/SendVerificationEmail
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationEmail([FromServices] IEmailService emailService, ChangeEmailViewModel model)
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
                return View(model);
            }

            var userId = await _userManager.GetUserIdAsync(user);
            
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Action("ConfirmEmail", "Account",
                new { area = "User", userId = userId, code = code },
                protocol: Request.Scheme) ?? string.Empty;
            await emailService.SendEmailAsync("identitytomvc@gmail.com" , email, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            model.StatusMessage = "Verification email sent. Please check your email.";
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
                return RedirectToPage("/Index");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ChangeEmailAsync(user, email, code);
            if (!result.Succeeded)
            {
                TempData["StatusMessage"] = "Error changing email.";
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
            TempData["StatusMessage"] = "Thank you for confirming your email change.";
            return View();
        }
    }
}
