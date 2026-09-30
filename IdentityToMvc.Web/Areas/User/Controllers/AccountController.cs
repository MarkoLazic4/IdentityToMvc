using IdentityToMvc.Web.Areas.User.ViewModels.Account;
using IdentityToMvc.Web.Helpers;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityToMvc.Web.Areas.User.Controllers
{
    [Area("User")]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        // ===========================================================================
        // GET: /User/Account/Register
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Register(string? returnUrl = null)
        {
            var viewModel = new RegisterViewModel
            {
                ReturnUrl = SanitizeReturnUrl(returnUrl),
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Register
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register([FromServices] IEmailService emailService, RegisterViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return View(model);

            var user = new IdentityUser
            {
                UserName = model.Input.Email,
                Email = model.Input.Email
            };

            var result = await _userManager.CreateAsync(user, model.Input.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");

                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = TokenEncoder.Encode(code);
                var callbackUrl = Url.Action(
                    nameof(ConfirmEmail), "Account", 
                    new { area = "User", userId = userId, code = code, returnUrl = model.ReturnUrl },
                    protocol: Request.Scheme) ?? string.Empty;

                await emailService.SendEmailAsync(model.Input.Email, "Confirm your email", EmailTemplates.ConfirmAccount(callbackUrl));

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return RedirectToAction(nameof(RegisterConfirmation), "Account", new { area = "User", email = model.Input.Email, returnUrl = model.ReturnUrl });
                }
                else
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(model.ReturnUrl);
                }
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        // ===========================================================================
        // GET: /User/Account/RegisterConfirmation
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> RegisterConfirmation([FromServices] IHostEnvironment env, string? email, string? returnUrl = null)
        {
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Index", "Home", new { area = "" });
            }

            returnUrl = SanitizeReturnUrl(returnUrl);

            var user = await _userManager.FindByEmailAsync(email);

            var viewModel = new RegisterConfirmationViewModel
            {
                Email = email,
                // Development only: show the confirmation link on the page so the flow can be
                // tested without an SMTP server. Never enable this in production.
                DisplayConfirmAccountLink = env.IsDevelopment()
                    && user != null
                    && !await _userManager.IsEmailConfirmedAsync(user),
            };

            // Unknown emails get the same page as known ones so the page can't be used
            // to find out which addresses have an account.
            if (viewModel.DisplayConfirmAccountLink && user != null)
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = TokenEncoder.Encode(code);
                viewModel.EmailConfirmationUrl = Url.Action(
                    nameof(ConfirmEmail), "Account",
                    new { area = "User", userId = userId, code = code, returnUrl = returnUrl },
                    protocol: Request.Scheme);
            }

            return View(viewModel);
        }

        // ===========================================================================
        // GET: /User/Account/ConfirmEmail
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string? userId, string? code)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            {
                return RedirectToAction("Index", "Home", new { area = "" });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            if (!TokenEncoder.TryDecode(code, out var token))
            {
                TempData["StatusMessage"] = "Error: the confirmation link is invalid or has expired.";
                return View();
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            TempData["StatusMessage"] = result.Succeeded
                ? "Thank you for confirming your email. You can now log in."
                : "Error: the confirmation link is invalid or has expired.";
            return View();
        }

        // ===========================================================================
        // GET: /User/Account/ResendEmailConfirmation
        // ===========================================================================
        [HttpGet]
        public IActionResult ResendEmailConfirmation()
        {
            var viewModel = new ResendEmailConfirmationViewModel();

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/ResendEmailConfirmation
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendEmailConfirmation([FromServices] IEmailService emailService, ResendEmailConfirmationViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            const string sentMessage = "If an unconfirmed account exists for that address, a verification email has been sent.";

            var user = await _userManager.FindByEmailAsync(model.Input.Email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                // Don't reveal whether the user exists or is already confirmed
                TempData["StatusMessage"] = sentMessage;
                return RedirectToAction(nameof(ResendEmailConfirmation), "Account", new { area = "User" });
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = TokenEncoder.Encode(code);
            var callbackUrl = Url.Action(
                nameof(ConfirmEmail), "Account",
                new { area = "User", userId = userId, code = code },
                protocol: Request.Scheme) ?? string.Empty;

            await emailService.SendEmailAsync(model.Input.Email, "Confirm your email", EmailTemplates.ConfirmAccount(callbackUrl));

            TempData["StatusMessage"] = sentMessage;
            return RedirectToAction(nameof(ResendEmailConfirmation), "Account", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Login
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Login(string? returnUrl = null)
        {
            var viewModel = new LoginViewModel();
            viewModel.ReturnUrl = SanitizeReturnUrl(returnUrl) ?? DefaultUrl();

            var errorMessage = TempData["ErrorMessage"] as string;

            if (!string.IsNullOrWhiteSpace(errorMessage))
            {
                ModelState.AddModelError(string.Empty, errorMessage);
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            viewModel.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Login
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                // Failed attempts count towards lockout (see Lockout options in Program.cs)
                var result = await _signInManager.PasswordSignInAsync(model.Input.Email, model.Input.Password, model.Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(model.ReturnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl = model.ReturnUrl, rememberMe = model.Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt. If you just registered, make sure you have confirmed your email.");
                    return View(model);
                }
            }

            return View(model);
        }

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
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
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
                ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return View(model);
            }
        }

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
                TempData["ErrorMessage"] = $"Error from external provider: {remoteError}";
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                TempData["ErrorMessage"] = "Error loading external login information.";
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            // bypassTwoFactor: false - users who enabled 2FA must still enter their code
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: false);
            if (result.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity?.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl, rememberMe = false });
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
            }
            if (result.IsNotAllowed)
            {
                TempData["ErrorMessage"] = "You need to confirm your email before you can log in.";
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl });
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                var viewModel = new ExternalLoginViewModel();
                viewModel.ReturnUrl = returnUrl;
                viewModel.ProviderDisplayName = info.ProviderDisplayName ?? info.LoginProvider;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    viewModel.Input = new ExternalLoginViewModel.InputModel
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email) ?? string.Empty
                    };
                }
                return View("ExternalLogin", viewModel);
            }
        }

        // ===========================================================================
        // POST: /User/Account/ExternalLoginConfirmation
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation([FromServices] IEmailService emailService, ExternalLoginViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            // Get the information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                TempData["ErrorMessage"] = "Error loading external login information during confirmation.";
                return RedirectToAction(nameof(Login), "Account", new { area = "User", returnUrl = model.ReturnUrl });
            }

            if (ModelState.IsValid)
            {
                var user = new IdentityUser
                {
                    UserName = model.Input.Email,
                    Email = model.Input.Email
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

                        var userId = await _userManager.GetUserIdAsync(user);
                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        code = TokenEncoder.Encode(code);
                        var callbackUrl = Url.Action(
                            nameof(ConfirmEmail), "Account", 
                            new { area = "User", userId = userId, code = code },
                            protocol: Request.Scheme) ?? string.Empty;

                        await emailService.SendEmailAsync(model.Input.Email, "Confirm your email", EmailTemplates.ConfirmAccount(callbackUrl));

                        // If account confirmation is required, we need to show the link if we don't have a real email sender
                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            return RedirectToAction(nameof(RegisterConfirmation), "Account", new { area = "User", email = model.Input.Email });
                        }

                        await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                        return LocalRedirect(model.ReturnUrl);
                    }
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            model.ProviderDisplayName = info.ProviderDisplayName ?? info.LoginProvider;
            return View("ExternalLogin", model);
        }


        // ===========================================================================
        // POST: /User/Account/Logout
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string? returnUrl = null)
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home", new { area = ""});
            }
        }

        // ===========================================================================
        // GET: /User/Account/Lockout
        // ===========================================================================
        [HttpGet]
        public IActionResult Lockout()
        {
            return View();
        }

        // ===========================================================================
        // GET: /User/Account/AccessDenied
        // ===========================================================================
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        // ===========================================================================
        // GET: /User/Account/ForgotPassword
        // ===========================================================================
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            var viewModel = new ForgotPasswordViewModel();

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/ForgotPassword
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword([FromServices] IEmailService emailService, ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Input.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToAction(nameof(ForgotPasswordConfirmation), "Account", new { area = "User" });
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = TokenEncoder.Encode(code);
                var callbackUrl = Url.Action(
                    nameof(ResetPassword), "Account",
                    new { area = "User", code },
                    protocol: Request.Scheme) ?? string.Empty;

                await emailService.SendEmailAsync(model.Input.Email, "Reset your password", EmailTemplates.ResetPassword(callbackUrl));

                return RedirectToAction(nameof(ForgotPasswordConfirmation), "Account", new { area = "User" });
            }

            return View(model);
        }

        // ===========================================================================
        // GET: /User/Account/ForgotPasswordConfirmation
        // ===========================================================================
        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        // ===========================================================================
        // GET: /User/Account/ResetPassword 
        // ===========================================================================
        [HttpGet]
        public IActionResult ResetPassword(string? code = null)
        {
            if (!TokenEncoder.TryDecode(code, out var token))
            {
                TempData["StatusMessage"] = "Error: the password reset link is invalid. Please request a new one.";
                return RedirectToAction(nameof(ForgotPassword), "Account", new { area = "User" });
            }

            var viewModel = new ResetPasswordViewModel
            {
                Input = new ResetPasswordViewModel.InputModel
                {
                    Code = token
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/ResetPassword
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _userManager.FindByEmailAsync(model.Input.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(ResetPasswordConfirmation), "Account", new { area = "User" });
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Input.Code, model.Input.Password);
            if (result.Succeeded)
            {
                // The user proved they own the mailbox, so lift any lockout from failed logins
                await _userManager.ResetAccessFailedCountAsync(user);
                await _userManager.SetLockoutEndDateAsync(user, null);
                return RedirectToAction(nameof(ResetPasswordConfirmation), "Account", new { area = "User" });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // ===========================================================================
        // GET: /User/Account/ResetPasswordConfirmation
        // ===========================================================================
        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        private string? SanitizeReturnUrl(string? returnUrl)
        {
            if(string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
            {
                return null;
            }

            return returnUrl;
        }

        private string DefaultUrl()
        {
            return "/Home/Index";
        }
    }
}
