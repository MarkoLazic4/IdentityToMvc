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
    // Signed-in devices (sessions) and "sign out everywhere".
    public partial class ManageController
    {
        // ===========================================================================
        // POST: /User/Account/Manage/SignOutEverywhere
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignOutEverywhere()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // A new security stamp invalidates every existing auth and "remember this browser"
            // cookie at their next validation (see SecurityStampValidatorOptions).
            await _userManager.UpdateSecurityStampAsync(user);
            await _sessions.RevokeAllAsync(user.Id, exceptSessionId: SessionService.GetSessionId(User));
            await _signInManager.ForgetTwoFactorClientAsync();
            // Keep this session alive with a cookie carrying the new stamp
            await _signInManager.RefreshSignInAsync(user);
            await _recentAuthentication.MarkAsync(HttpContext, user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.SignedOutEverywhere);

            this.StatusSuccess(_t["All other devices were signed out."]);
            return RedirectToAction(nameof(Devices), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/Devices
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Devices(
            [FromServices] IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions> cookieOptions)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // A session whose cookie has expired (idle longer than the cookie lifetime) is gone anyway
            var maxIdle = cookieOptions.Get(IdentityConstants.ApplicationScheme).ExpireTimeSpan + TimeSpan.FromMinutes(10);
            var currentSessionId = SessionService.GetSessionId(User);
            var sessions = await _sessions.GetActiveAsync(user.Id, maxIdle);

            var viewModel = new DevicesViewModel
            {
                Devices = sessions.Select(session => new DevicesViewModel.DeviceItem
                {
                    Id = session.Id,
                    Device = session.Device ?? "Unknown device",
                    IpAddress = session.IpAddress,
                    CreatedAt = session.CreatedAt,
                    LastSeenAt = session.LastSeenAt,
                    IsCurrent = session.Id == currentSessionId
                })
                .OrderByDescending(d => d.IsCurrent)
                .ToList()
            };
            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/RevokeSession
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RevokeSession(string id)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (id == SessionService.GetSessionId(User))
            {
                this.StatusError(_t["Use Log out to end the session on this device."]);
            }
            else if (await _sessions.RevokeAsync(user.Id, id))
            {
                await _securityNotifier.NotifyAsync(user, SecurityEvent.SessionRevoked);
                this.StatusSuccess(_t["The device was signed out."]);
            }
            else
            {
                this.StatusError(_t["That device is no longer signed in."]);
            }
            return RedirectToAction(nameof(Devices), "Manage", new { area = "User" });
        }
    }
}
