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
    // Changing the email address.
    public partial class ManageController
    {
        // ===========================================================================
        // GET: /User/Account/Manage/Email
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Email()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var email = await _userManager.GetEmailAsync(user);
            var viewModel = new ChangeEmailViewModel 
            { 
                Email = email,
                IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user),
                Input = new ChangeEmailViewModel.InputModel
                {
                    NewEmail = email ?? string.Empty
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/ChangeEmail
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> ChangeEmail([FromServices] IEmailService emailService, ChangeEmailViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var email = await _userManager.GetEmailAsync(user);

            if (!ModelState.IsValid)
            {
                model.Email = email;
                model.IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
                model.Input.NewEmail = email ?? string.Empty;
                return View(nameof(Email), model);
            }

            if (!string.Equals(model.Input.NewEmail, email, StringComparison.OrdinalIgnoreCase))
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateChangeEmailTokenAsync(user, model.Input.NewEmail);
                code = TokenEncoder.Encode(code);
                var callbackUrl = Url.Action(nameof(ConfirmEmailChange), "Manage",
                    new { area = "User", userId = userId, email = model.Input.NewEmail, code = code },
                    protocol: Request.Scheme) ?? string.Empty;
                var sent = await emailService.SendEmailAsync(model.Input.NewEmail, _templates.ConfirmEmailChangeSubject, _templates.ConfirmEmailChange(callbackUrl));
                if (sent)
                {
                    // Warn the current address too, in case someone else is trying to take over the account
                    await _securityNotifier.NotifyAsync(user, SecurityEvent.EmailChangeRequested);
                }

                if (sent)
                    this.StatusSuccess(_t["Confirmation link to change email sent. Please check your email."]);
                else
                    this.StatusError(_t["The confirmation email could not be sent. Please try again later."]);
                return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
            }

            this.StatusSuccess(_t["Your email is unchanged."]);
            return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // POST: /User/Account/Manage/SendVerificationEmail
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationEmail([FromServices] IEmailService emailService)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // The "new email" field posted with this form is irrelevant here, so ModelState is not checked
            var email = await _userManager.GetEmailAsync(user);

            if (string.IsNullOrEmpty(email))
            {
                this.StatusError(_t["Your account has no email address."]);
                return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
            }

            var userId = await _userManager.GetUserIdAsync(user);

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = TokenEncoder.Encode(code);
            var callbackUrl = Url.Action("ConfirmEmail", "Account",
                new { area = "User", userId = userId, code = code },
                protocol: Request.Scheme) ?? string.Empty;
            var sent = await emailService.SendEmailAsync(email, _templates.ConfirmAccountSubject, _templates.ConfirmAccount(callbackUrl));

            if (sent)
                this.StatusSuccess(_t["Verification email sent. Please check your email."]);
            else
                this.StatusError(_t["The verification email could not be sent. Please try again later."]);
            return RedirectToAction(nameof(Email), "Manage", new { area = "User" });
        }

        // ===========================================================================
        // GET: /User/Account/Manage/ConfirmEmailChange
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> ConfirmEmailChange(string? userId, string? email, string? code)
        {
            if (userId == null || email == null || code == null)
            {
                return RedirectToAction("Index", "Home", new { area = "" });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            // The link is only valid for the account it was sent from
            if (!string.Equals(_userManager.GetUserId(User), userId, StringComparison.Ordinal))
            {
                this.StatusError(_t["Log in with the account that requested the email change and open the link again."]);
                return View();
            }

            if (!TokenEncoder.TryDecode(code, out var token))
            {
                this.StatusError(_t["The confirmation link is invalid or has expired."]);
                return View();
            }

            var oldEmail = await _userManager.GetEmailAsync(user);
            var result = await _userManager.ChangeEmailAsync(user, email, token);
            if (!result.Succeeded)
            {
                this.StatusError(_t["Error changing email. The link may have expired or the address is already in use."]);
                return View();
            }

            // In our UI email and user name are one and the same, so when we update the email
            // we need to update the user name.
            var setUserNameResult = await _userManager.SetUserNameAsync(user, email);
            if (!setUserNameResult.Succeeded)
            {
                this.StatusError(_t["Error changing user name."]);
                return View();
            }

            await _signInManager.RefreshSignInAsync(user);
            await _securityNotifier.NotifyAsync(user, SecurityEvent.EmailChanged, overrideEmail: oldEmail);
            this.StatusSuccess(_t["Thank you for confirming your email change."]);
            return View();
        }
    }
}
