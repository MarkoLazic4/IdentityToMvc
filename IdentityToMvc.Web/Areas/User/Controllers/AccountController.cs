using IdentityToMvc.Web.Areas.User.ViewModels.Account;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Shared;

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
                    return RedirectToPage(nameof(RegisterConfirmation), new { email = model.Input.Email, returnUrl = model.ReturnUrl });
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
            TempData["StatusType"] = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
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
