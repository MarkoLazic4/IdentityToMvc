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
    // Unlock link from the "your account was locked" email.
    public partial class AccountController
    {
        private const string UnlockTokenPurpose = "UnlockAccount";


        // ===========================================================================
        // GET: /User/Account/Unlock  (link from the "account locked" email)
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Unlock(string? userId, string? code)
        {
            var user = string.IsNullOrEmpty(userId) ? null : await _userManager.FindByIdAsync(userId);
            if (user != null
                && TokenEncoder.TryDecode(code, out var token)
                && await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, UnlockTokenPurpose, token)
                && !IsLockedByAdministrator(await _userManager.GetLockoutEndDateAsync(user)))
            {
                await _userManager.SetLockoutEndDateAsync(user, null);
                await _userManager.ResetAccessFailedCountAsync(user);
                await _securityNotifier.NotifyAsync(user, SecurityEvent.AccountUnlocked);
                this.StatusSuccess(_t["Your account is unlocked. You can log in now."]);
            }
            else
            {
                this.StatusError(_t["The unlock link is invalid or has expired."]);
            }
            return RedirectToAction(nameof(Login), "Account", new { area = "User" });
        }
    }
}
