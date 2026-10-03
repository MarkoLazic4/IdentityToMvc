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
    // Managing passkeys (WebAuthn).
    public partial class ManageController
    {
        // ===========================================================================
        // GET: /User/Account/Manage/Passkeys
        // ===========================================================================
        [HttpGet]
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> Passkeys([FromServices] IOptionsMonitor<SecurityOptions> securityOptions)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var passkeys = await _userManager.GetPasskeysAsync(user);
            var viewModel = new PasskeysViewModel
            {
                MaxPasskeys = securityOptions.CurrentValue.MaxPasskeysPerUser,
                Passkeys = passkeys
                    .OrderBy(p => p.CreatedAt)
                    .Select(p => new PasskeysViewModel.PasskeyItem
                    {
                        Id = WebEncoders.Base64UrlEncode(p.CredentialId),
                        Name = string.IsNullOrWhiteSpace(p.Name) ? "Unnamed passkey" : p.Name,
                        CreatedAt = p.CreatedAt,
                        IsBackedUp = p.IsBackedUp
                    })
                    .ToList()
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/PasskeyCreationOptions  (called from JavaScript)
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> PasskeyCreationOptions()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var userName = await _userManager.GetUserNameAsync(user) ?? "User";
            var optionsJson = await _signInManager.MakePasskeyCreationOptionsAsync(new PasskeyUserEntity
            {
                Id = await _userManager.GetUserIdAsync(user),
                Name = userName,
                DisplayName = userName
            });
            return Content(optionsJson, "application/json");
        }

        // ===========================================================================
        // POST: /User/Account/Manage/AddPasskey
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> AddPasskey([FromServices] IOptionsMonitor<SecurityOptions> securityOptions,
            string? credentialJson, string? name)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (string.IsNullOrWhiteSpace(credentialJson))
            {
                this.StatusError(_t["The passkey registration was cancelled."]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var existing = await _userManager.GetPasskeysAsync(user);
            if (existing.Count >= securityOptions.CurrentValue.MaxPasskeysPerUser)
            {
                this.StatusError(_t["You can register at most {0} passkeys.", securityOptions.CurrentValue.MaxPasskeysPerUser]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var attestation = await _signInManager.PerformPasskeyAttestationAsync(credentialJson);
            if (!attestation.Succeeded)
            {
                _logger.LogWarning("Passkey attestation failed for user {UserId}: {Error}", user.Id, attestation.Failure?.Message);
                this.StatusError(_t["The passkey could not be verified. Please try again."]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var passkey = attestation.Passkey;
            passkey.Name = string.IsNullOrWhiteSpace(name) ? "Passkey" : name.Trim()[..Math.Min(name.Trim().Length, 50)];
            var result = await _userManager.AddOrUpdatePasskeyAsync(user, passkey);
            if (!result.Succeeded)
            {
                this.StatusError(_t["The passkey could not be saved."]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasskeyAdded);
            this.StatusSuccess(_t["Passkey \"{0}\" was added. You can now use it to log in.", passkey.Name]);
            return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/RemovePasskey
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        [FeatureGate(SecurityFeature.Passkeys)]
        public async Task<IActionResult> RemovePasskey(string id)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            byte[] credentialId;
            try
            {
                credentialId = WebEncoders.Base64UrlDecode(id ?? string.Empty);
            }
            catch (FormatException)
            {
                return BadRequest();
            }

            // Never remove the last way to log in
            var hasPassword = await _userManager.HasPasswordAsync(user);
            var logins = await _userManager.GetLoginsAsync(user);
            var passkeys = await _userManager.GetPasskeysAsync(user);
            if (!hasPassword && logins.Count == 0 && passkeys.Count <= 1)
            {
                this.StatusError(_t["You can't remove your only way to log in. Set a password first."]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            var result = await _userManager.RemovePasskeyAsync(user, credentialId);
            if (!result.Succeeded)
            {
                this.StatusError(_t["The passkey was not found."]);
                return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
            }

            await _securityNotifier.NotifyAsync(user, SecurityEvent.PasskeyRemoved);
            this.StatusSuccess(_t["The passkey was removed."]);
            return RedirectToAction(nameof(Passkeys), "Manage", new { area = "User" });
        }
    }
}
