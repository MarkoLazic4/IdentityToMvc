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
    // Personal data: download and account deletion (GDPR).
    public partial class ManageController
    {
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
                    ModelState.AddModelError(string.Empty, _t["Incorrect password."]);
                    return View(model);
                }
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, _t["Unexpected error occurred deleting your account."]);
                return View(model);
            }

            await _signInManager.SignOutAsync();
            _recentAuthentication.Clear(HttpContext);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.AccountDeleted);

            _logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

            return RedirectToAction("Index", "Home", new { area = "" });
        }
    }
}
