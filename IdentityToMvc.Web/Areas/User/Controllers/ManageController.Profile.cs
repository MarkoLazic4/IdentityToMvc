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
    // Profile page (phone number).
    public partial class ManageController
    {
        // ===========================================================================
        // GET: /User/Account/Manage/Index
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var viewModel = new IndexViewModel()
            { 
                Username = await _userManager.GetUserNameAsync(user) ?? string.Empty,
                Input = new IndexViewModel.InputModel
                {
                    PhoneNumber = await _userManager.GetPhoneNumberAsync(user)
                }
            };

            return View(viewModel);
        }

        // ===========================================================================
        // POST: /User/Account/Manage/Index
        // ===========================================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(IndexViewModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model.Username = await _userManager.GetUserNameAsync(user) ?? string.Empty;
                model.Input = new IndexViewModel.InputModel
                {
                    PhoneNumber = await _userManager.GetPhoneNumberAsync(user)
                };
                return View(model);
            }

            var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
            if (model.Input.PhoneNumber != phoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.Input.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    this.StatusError(_t["Unexpected error when trying to set phone number."]);
                    return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
                }
            }

            await _signInManager.RefreshSignInAsync(user);
            this.StatusSuccess(_t["Your profile has been updated"]);
            return RedirectToAction(nameof(Index), "Manage", new { area = "User" });
        }
    }
}
