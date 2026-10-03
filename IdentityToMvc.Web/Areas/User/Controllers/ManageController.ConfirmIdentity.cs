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
    // "Confirm it's you" page for sudo mode (see Security/RecentAuthentication.cs).
    public partial class ManageController
    {
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
                ModelState.AddModelError(string.Empty, _t["Incorrect password."]);
                return View(model);
            }

            await _recentAuthentication.MarkAsync(HttpContext, user);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return LocalRedirect(model.ReturnUrl);
            }
            return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
        }
    }
}
