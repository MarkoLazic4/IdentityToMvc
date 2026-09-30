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
    [Area("User")]
    [Authorize]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [TypeFilter(typeof(RefreshSessionOnSecurityStampChangeFilter))]
    [Route("{area}/Account/[controller]/[action]")]
    public partial class ManageController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISecurityNotifier _securityNotifier;
        private readonly RecentAuthenticationService _recentAuthentication;
        private readonly SessionService _sessions;
        private readonly EmailTemplates _templates;
        private readonly IStringLocalizer<SharedResource> _t;
        private readonly ILogger<ManageController> _logger;

        public ManageController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ISecurityNotifier securityNotifier, RecentAuthenticationService recentAuthentication, SessionService sessions,
            EmailTemplates templates, IStringLocalizer<SharedResource> localizer, ILogger<ManageController> logger)
        {
            _sessions = sessions;
            _templates = templates;
            _t = localizer;
            _userManager = userManager;
            _signInManager = signInManager;
            _securityNotifier = securityNotifier;
            _recentAuthentication = recentAuthentication;
            _logger = logger;
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
            this.StatusSuccess(_t["Your password has been changed. Your other sessions will be signed out."]);

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
            this.StatusSuccess(_t["Your password has been set."]);

            return RedirectToAction(nameof(SetPassword), "Manage", new { area = "User" });
        }
    }
}
