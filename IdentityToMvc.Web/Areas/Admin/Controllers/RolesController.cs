using IdentityToMvc.Web.Areas.Admin.ViewModels;
using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Localization;
using IdentityToMvc.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;

namespace IdentityToMvc.Web.Areas.Admin.Controllers
{
    public class RolesController : AdminControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _db;
        private readonly IStringLocalizer<SharedResource> _t;

        public RolesController(RoleManager<IdentityRole> roleManager, ApplicationDbContext db, IStringLocalizer<SharedResource> localizer)
        {
            _roleManager = roleManager;
            _db = db;
            _t = localizer;
        }

        // GET: /Admin/Roles
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var counts = await _db.UserRoles.GroupBy(ur => ur.RoleId)
                .Select(g => new { RoleId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(x => x.RoleId, x => x.Count);

            var roles = await _roleManager.Roles.OrderBy(r => r.Name).ToListAsync();
            return View(new RolesViewModel
            {
                Roles = roles.Select(r => new RolesViewModel.RoleRow
                {
                    Name = r.Name ?? r.Id,
                    UserCount = counts.TryGetValue(r.Id, out var count) ? count : 0,
                    IsProtected = r.Name == AdminBootstrapper.AdminRole
                }).ToList()
            });
        }

        // POST: /Admin/Roles/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> Create(string? name)
        {
            name = name?.Trim();
            if (string.IsNullOrEmpty(name) || name.Length > 64 || !name.All(c => char.IsLetterOrDigit(c) || c is '-' or '_' or ' '))
            {
                this.StatusError(_t["Role names can contain letters, digits, spaces, '-' and '_' (up to 64 characters)."]);
                return RedirectToAction(nameof(Index));
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(name));
            if (result.Succeeded)
                this.StatusSuccess(_t["The role {0} was created.", name]);
            else
                this.StatusError(string.Join(" ", result.Errors.Select(e => e.Description)));
            return RedirectToAction(nameof(Index));
        }

        // POST: /Admin/Roles/Delete
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> Delete(string name)
        {
            if (name == AdminBootstrapper.AdminRole)
            {
                this.StatusError(_t["The Admin role can't be deleted."]);
                return RedirectToAction(nameof(Index));
            }

            var role = await _roleManager.FindByNameAsync(name);
            if (role != null)
            {
                await _roleManager.DeleteAsync(role);
                this.StatusSuccess(_t["The role {0} was deleted.", name]);
            }
            return RedirectToAction(nameof(Index));
        }
    }
}
