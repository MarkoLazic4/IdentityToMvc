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
    // Security activity timeline.
    public partial class ManageController
    {
        // ===========================================================================
        // GET: /User/Account/Manage/Activity
        // ===========================================================================
        [HttpGet]
        public async Task<IActionResult> Activity([FromServices] Data.ApplicationDbContext db)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var events = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.ToListAsync(
                db.SecurityEvents.Where(e => e.UserId == user.Id).OrderByDescending(e => e.CreatedAt).Take(50));
            return View(new ActivityViewModel { Events = events });
        }
    }
}
