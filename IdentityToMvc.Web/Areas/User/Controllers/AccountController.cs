using IdentityToMvc.Web.Areas.User.ViewModels.Account;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;
using System.Text;
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
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Action(
                    nameof(ConfirmEmail), "Account", 
                    new { area = "User", userId = userId, code = code, returnUrl = model.ReturnUrl },
                    protocol: Request.Scheme) ?? string.Empty;

                await emailService.SendEmailAsync("identitytomvc@gmail.com", model.Input.Email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

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
            if (user == null)
            {
                return NotFound($"Unable to load user with email '{email}'.");
            }

            var viewModel = new RegisterConfirmationViewModel
            {
                Email = email,
                // Once you add a real email sender, you should remove this code that lets you confirm the account
                //DisplayConfirmAccountLink = true;
                DisplayConfirmAccountLink = env.IsDevelopment(),
            };

            if (viewModel.DisplayConfirmAccountLink)
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
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

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);
            TempData["StatusMessage"] = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
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

            var user = await _userManager.FindByEmailAsync(model.Input.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Verification email sent. Please check your email.");
                return View(model);
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Action(
                nameof(ConfirmEmail), "Account",
                new { area = "User", userId = userId, code = code },
                protocol: Request.Scheme) ?? string.Empty;

            await emailService.SendEmailAsync("identitytomvc@gmail.com", model.Input.Email, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            ModelState.AddModelError(string.Empty, "Verification email sent. Please check your email.");
            return View(model);
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
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(model.Input.Email, model.Input.Password, model.Input.RememberMe, lockoutOnFailure: false);
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
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
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
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
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
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var authenticatorCode = model.Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, model.RememberMe, model.Input.RememberMachine);

            var userId = await _userManager.GetUserIdAsync(user);

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
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
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
            // Normalizuj i sanitize-uj returnUrl
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl);

            if (!ModelState.IsValid)
                return View(model);

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.Input.RecoveryCode.Replace(" ", string.Empty);

            var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

            var userId = await _userManager.GetUserIdAsync(user);

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
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                var viewModel = new ExternalLoginViewModel();
                viewModel.ReturnUrl = returnUrl;
                viewModel.ProviderDisplayName = info.ProviderDisplayName;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    viewModel.Input = new ExternalLoginViewModel.InputModel
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
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
                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);

                        var userId = await _userManager.GetUserIdAsync(user);
                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                        var callbackUrl = Url.Action(
                            nameof(ConfirmEmail), "Account", 
                            new { area = "User", userId = userId, code = code },
                            protocol: Request.Scheme) ?? string.Empty;

                        await emailService.SendEmailAsync("identitytomvc@gmail.com", model.Input.Email, "Confirm your email",
                            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

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

            model.ProviderDisplayName = info.ProviderDisplayName ?? string.Empty;
            return View("ExternalLogin", model);
        }


        // ===========================================================================
        // GET: /User/Account/Logout
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
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Action(
                    nameof(ResetPassword), "Account",
                    new { area = "User", code },
                    protocol: Request.Scheme) ?? string.Empty;

                await emailService.SendEmailAsync("identitytomvc@gmail.com", model.Input.Email,"Reset Password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

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
            if (string.IsNullOrWhiteSpace(code))
            {
                return BadRequest("A code must be supplied for password reset.");
            }

            var viewModel = new ResetPasswordViewModel
            {
                Input = new ResetPasswordViewModel.InputModel
                {
                    Code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code))
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/ResetPassword
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword([FromServices] IHostEnvironment env, ResetPasswordViewModel model)
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
