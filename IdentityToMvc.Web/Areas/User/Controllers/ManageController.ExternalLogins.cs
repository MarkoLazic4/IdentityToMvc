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
    // Linking and removing external logins (Google, Facebook).
    public partial class ManageController
    {
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
                this.StatusError(_t["You can't remove your only login. Set a password first."]);
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            var result = await _userManager.RemoveLoginAsync(user, loginProvider, providerKey);
            if (!result.Succeeded)
            {
                this.StatusError(_t["The external login was not removed."]);
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            await _signInManager.RefreshSignInAsync(user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.ExternalLoginRemoved);
            this.StatusSuccess(_t["The external login was removed."]);
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
                this.StatusError(_t["Unexpected error occurred loading external login info."]);
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            var result = await _userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                this.StatusError(_t["The external login was not added. External logins can only be associated with one account."]);
                return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
            }

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            await _securityNotifier.NotifyAsync(user, SecurityEvent.ExternalLoginAdded);
            this.StatusSuccess(_t["The external login was added."]);
            return RedirectToAction(nameof(ExternalLogins), "Manage", new { area = "User" });
        }
    }
}
