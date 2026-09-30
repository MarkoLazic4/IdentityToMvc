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
    [Area("User")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    public partial class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailQueue _emailQueue;
        private readonly ISecurityNotifier _securityNotifier;
        private readonly PasswordTimingEqualizer _timingEqualizer;
        private readonly SessionService _sessions;
#if (Admin)
        private readonly AdminBootstrapper _adminBootstrapper;
#endif
        private readonly EmailTemplates _templates;
        private readonly IStringLocalizer<SharedResource> _t;
        private readonly ILogger<AccountController> _logger;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            IEmailQueue emailQueue, ISecurityNotifier securityNotifier, PasswordTimingEqualizer timingEqualizer,
            SessionService sessions, EmailTemplates templates, IStringLocalizer<SharedResource> localizer,
#if (Admin)
            AdminBootstrapper adminBootstrapper,
#endif
            ILogger<AccountController> logger)
        {
#if (Admin)
            _adminBootstrapper = adminBootstrapper;
#endif
            _sessions = sessions;
            _templates = templates;
            _t = localizer;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailQueue = emailQueue;
            _securityNotifier = securityNotifier;
            _timingEqualizer = timingEqualizer;
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
        [EnableRateLimiting(RateLimitPolicies.Email)]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            model.ReturnUrl = SanitizeReturnUrl(model.ReturnUrl) ?? DefaultUrl();
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return View(model);

            var existing = await _userManager.FindByEmailAsync(model.Input.Email);
            if (existing != null)
            {
                if (await _userManager.IsEmailConfirmedAsync(existing))
                {
                    // Don't reveal that the address is taken: answer exactly like a new registration
                    // and tell the real owner by email instead.
                    _timingEqualizer.HashDummy(model.Input.Password);
                    var loginUrl = Url.Action(nameof(Login), "Account", new { area = "User" }, Request.Scheme) ?? string.Empty;
                    var resetUrl = Url.Action(nameof(ForgotPassword), "Account", new { area = "User" }, Request.Scheme) ?? string.Empty;
                    _emailQueue.Enqueue(model.Input.Email, _templates.AccountAlreadyExistsSubject, _templates.AccountAlreadyExists(loginUrl, resetUrl));
                    return RedirectToAction(nameof(RegisterConfirmation), "Account", new { area = "User", email = model.Input.Email, returnUrl = model.ReturnUrl });
                }

                // An unconfirmed account proves nothing about who owns the address. Replace it, so
                // nobody can "reserve" someone else's email with credentials they know
                // (pre-account-takeover). Whoever confirms the new email owns the account.
                _logger.LogInformation("Replacing unconfirmed account {UserId} with a new registration.", existing.Id);
                await _userManager.DeleteAsync(existing);
            }

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

                _emailQueue.Enqueue(model.Input.Email, _templates.ConfirmAccountSubject, _templates.ConfirmAccount(callbackUrl));

                if (_userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return RedirectToAction(nameof(RegisterConfirmation), "Account", new { area = "User", email = model.Input.Email, returnUrl = model.ReturnUrl });
                }
                else
                {
                    RecentAuthenticationService.FlagFreshSignIn(HttpContext);
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
                this.StatusError(_t["The confirmation link is invalid or has expired."]);
                return View();
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
#if (Admin)
                await _adminBootstrapper.EnsureAdminAsync(user);
#endif
                this.StatusSuccess(_t["Thank you for confirming your email. You can now log in."]);
            }
            else
            {
                this.StatusError(_t["The confirmation link is invalid or has expired."]);
            }
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
        [EnableRateLimiting(RateLimitPolicies.Email)]
        public async Task<IActionResult> ResendEmailConfirmation(ResendEmailConfirmationViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var sentMessage = _t["If an unconfirmed account exists for that address, a verification email has been sent."];

            var user = await _userManager.FindByEmailAsync(model.Input.Email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                // Don't reveal whether the user exists or is already confirmed
                this.StatusSuccess(sentMessage);
                return RedirectToAction(nameof(ResendEmailConfirmation), "Account", new { area = "User" });
            }

            // The resent link doesn't just confirm the existing account - it makes the recipient choose
            // a new password. If someone else registered this address, their password stops working.
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            code = TokenEncoder.Encode(code);
            var callbackUrl = Url.Action(
                nameof(ResetPassword), "Account",
                new { area = "User", code, activate = true },
                protocol: Request.Scheme) ?? string.Empty;

            _emailQueue.Enqueue(model.Input.Email, _templates.FinishSetupSubject, _templates.FinishSetup(callbackUrl));

            this.StatusSuccess(sentMessage);
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
                // Identity skips the slow password check for unknown, unconfirmed or locked-out
                // accounts; do an equivalent check so timing doesn't reveal which accounts exist.
                var candidate = await _userManager.FindByEmailAsync(model.Input.Email);
                if (candidate == null
                    || !await _signInManager.CanSignInAsync(candidate)
                    || await _userManager.IsLockedOutAsync(candidate))
                {
                    _timingEqualizer.VerifyDummy(model.Input.Password);
                }

                RecentAuthenticationService.FlagFreshSignIn(HttpContext);
                var result = await _signInManager.PasswordSignInAsync(model.Input.Email, model.Input.Password, model.Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(model.ReturnUrl);
                }
#if (TwoFactor)
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl = model.ReturnUrl, rememberMe = model.Input.RememberMe });
                }
#endif
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    await NotifyIfJustLockedOutAsync(model.Input.Email);
                    return RedirectToAction(nameof(Lockout), "Account", new { area = "User" });
                }
                else
                {
                    if (candidate != null)
                    {
                        await _securityNotifier.NotifyAsync(candidate, SecurityEvent.LoginFailed, sendEmail: false);
                    }
                    ModelState.AddModelError(string.Empty, _t["Invalid login attempt. If you just registered, make sure you have confirmed your email."]);
                    return View(model);
                }
            }

            return View(model);
        }

        // ===========================================================================
        // POST: /User/Account/Logout
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string? returnUrl = null)
        {
            var sessionId = SessionService.GetSessionId(User);
            var userId = _userManager.GetUserId(User);
            if (sessionId != null && userId != null)
            {
                await _sessions.RevokeAsync(userId, sessionId);
            }
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
        [EnableRateLimiting(RateLimitPolicies.Email)]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
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

                _emailQueue.Enqueue(model.Input.Email, _templates.ResetPasswordSubject, _templates.ResetPassword(callbackUrl));

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
        public IActionResult ResetPassword(string? code = null, bool activate = false)
        {
            if (!TokenEncoder.TryDecode(code, out var token))
            {
                this.StatusError(_t["The password reset link is invalid. Please request a new one."]);
                return RedirectToAction(nameof(ForgotPassword), "Account", new { area = "User" });
            }

            var viewModel = new ResetPasswordViewModel
            {
                IsActivation = activate,
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

            string invalidLink = _t["The password reset link is invalid or has expired, or the email doesn't match. Please request a new link."];

            var user = await _userManager.FindByEmailAsync(model.Input.Email);
            if (user == null)
            {
                // Same answer as an invalid token, so the form can't be used to probe for accounts
                ModelState.AddModelError(string.Empty, invalidLink);
                return View(model);
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Input.Code, model.Input.Password);
            if (result.Succeeded)
            {
                // The user proved they own the mailbox, so lift any lockout from failed logins -
                // but never a lock set by an administrator.
                // ResetPasswordAsync also rotates the security stamp, signing out every other session.
                await _userManager.ResetAccessFailedCountAsync(user);
                if (!IsLockedByAdministrator(await _userManager.GetLockoutEndDateAsync(user)))
                {
                    await _userManager.SetLockoutEndDateAsync(user, null);
                }

                // The reset link was delivered to the mailbox, which proves ownership of the address
                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    var confirmToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    await _userManager.ConfirmEmailAsync(user, confirmToken);
#if (Admin)
                    await _adminBootstrapper.EnsureAdminAsync(user);
#endif
                }
                await _securityNotifier.NotifyAsync(user, SecurityEvent.PasswordReset);
                return RedirectToAction(nameof(ResetPasswordConfirmation), "Account", new { area = "User" });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Code == nameof(IdentityErrorDescriber.InvalidToken) ? invalidLink : error.Description);
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

        /// <summary>
        /// Emails the owner when this login attempt is the one that locked the account
        /// (not on every attempt made while it is already locked).
        /// </summary>
        private async Task NotifyIfJustLockedOutAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var lockoutEnd = user == null ? null : await _userManager.GetLockoutEndDateAsync(user);
            if (user != null && lockoutEnd.HasValue
                && lockoutEnd.Value - DateTimeOffset.UtcNow > _userManager.Options.Lockout.DefaultLockoutTimeSpan - TimeSpan.FromSeconds(10))
            {
                await _securityNotifier.NotifyAsync(user, SecurityEvent.AccountLockedOut, sendEmail: false);

#if (UnlockLink)
                // Give the owner a way out: an attacker who keeps locking the account can't keep them out
                var code = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, UnlockTokenPurpose);
                var callbackUrl = Url.Action(nameof(Unlock), "Account",
                    new { area = "User", userId = user.Id, code = TokenEncoder.Encode(code) }, Request.Scheme) ?? string.Empty;
                _emailQueue.Enqueue(email, _templates.UnlockAccountSubject, _templates.UnlockAccount(callbackUrl));
#endif
            }
        }

        /// <summary>
        /// Locks set by an administrator last (practically) forever; failed-attempt lockouts last minutes.
        /// Only the latter can be lifted by a passkey or the unlock link.
        /// </summary>
        private static bool IsLockedByAdministrator(DateTimeOffset? lockoutEnd) =>
            lockoutEnd.HasValue && lockoutEnd.Value > DateTimeOffset.UtcNow.AddYears(1);

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
