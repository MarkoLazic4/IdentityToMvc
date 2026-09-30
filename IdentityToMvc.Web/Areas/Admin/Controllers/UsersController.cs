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
    public class UsersController : AdminControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _db;
        private readonly SessionService _sessions;
        private readonly ISecurityNotifier _notifier;
        private readonly AdminBootstrapper _adminBootstrapper;
        private readonly IStringLocalizer<SharedResource> _t;
        private readonly ILogger<UsersController> _logger;

        public UsersController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
            ApplicationDbContext db, SessionService sessions, ISecurityNotifier notifier, AdminBootstrapper adminBootstrapper,
            IStringLocalizer<SharedResource> localizer, ILogger<UsersController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _db = db;
            _sessions = sessions;
            _notifier = notifier;
            _adminBootstrapper = adminBootstrapper;
            _t = localizer;
            _logger = logger;
        }

        /// <summary>Administrator locks never expire on their own (failed-login lockouts last minutes).</summary>
        private static readonly DateTimeOffset AdminLockEnd = DateTimeOffset.MaxValue;

        private static bool IsAdminLock(DateTimeOffset? end) => end.HasValue && end.Value > DateTimeOffset.UtcNow.AddYears(1);

        // GET: /Admin/Users?q=...&page=1
        [HttpGet]
        public async Task<IActionResult> Index(string? q, int page = 1)
        {
            var query = _userManager.Users;
            if (!string.IsNullOrWhiteSpace(q))
            {
                var term = q.Trim().ToUpperInvariant();
                query = query.Where(u => u.NormalizedEmail!.Contains(term));
            }

            var total = await query.CountAsync();
            var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)PageSize));
            page = Math.Clamp(page, 1, totalPages);

            var users = await query.OrderBy(u => u.Email).Skip((page - 1) * PageSize).Take(PageSize).ToListAsync();
            var ids = users.Select(u => u.Id).ToList();
            var lastActive = await _db.UserSessions
                .Where(s => ids.Contains(s.UserId))
                .GroupBy(s => s.UserId)
                .Select(g => new { UserId = g.Key, LastSeen = g.Max(s => s.LastSeenAt) })
                .ToDictionaryAsync(x => x.UserId, x => x.LastSeen);

            var rows = new List<UserListViewModel.UserRow>();
            foreach (var user in users)
            {
                rows.Add(new UserListViewModel.UserRow
                {
                    Id = user.Id,
                    Email = user.Email ?? user.UserName ?? user.Id,
                    EmailConfirmed = user.EmailConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    IsLocked = user.LockoutEnd > DateTimeOffset.UtcNow,
                    IsAdminLock = IsAdminLock(user.LockoutEnd),
                    Roles = await _userManager.GetRolesAsync(user),
                    LastActive = lastActive.TryGetValue(user.Id, out var seen) ? seen : null
                });
            }

            return View(new UserListViewModel { Query = q, Page = page, TotalPages = totalPages, TotalCount = total, Users = rows });
        }

        // GET: /Admin/Users/Details/{id}
        [HttpGet]
        public async Task<IActionResult> Details(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            var hourAgo = DateTime.UtcNow.AddHours(-2);
            var viewModel = new UserDetailsViewModel
            {
                Id = user.Id,
                Email = user.Email ?? user.UserName ?? user.Id,
                PhoneNumber = user.PhoneNumber,
                EmailConfirmed = user.EmailConfirmed,
                TwoFactorEnabled = user.TwoFactorEnabled,
                HasPassword = await _userManager.HasPasswordAsync(user),
                PasskeyCount = (await _userManager.GetPasskeysAsync(user)).Count,
                AccessFailedCount = user.AccessFailedCount,
                LockoutEnd = user.LockoutEnd,
                IsLocked = user.LockoutEnd > DateTimeOffset.UtcNow,
                IsAdminLock = IsAdminLock(user.LockoutEnd),
                IsCurrentUser = user.Id == _userManager.GetUserId(User),
                ExternalLogins = (await _userManager.GetLoginsAsync(user)).Select(l => l.ProviderDisplayName ?? l.LoginProvider).ToList(),
                Roles = await _userManager.GetRolesAsync(user),
                AllRoles = await _roleManager.Roles.OrderBy(r => r.Name).Select(r => r.Name!).ToListAsync(),
                Sessions = await _db.UserSessions.Where(s => s.UserId == user.Id && s.RevokedAt == null && s.LastSeenAt >= hourAgo)
                    .OrderByDescending(s => s.LastSeenAt).ToListAsync(),
                Events = await _db.SecurityEvents.Where(e => e.UserId == user.Id).OrderByDescending(e => e.CreatedAt).Take(20).ToListAsync()
            };
            return View(viewModel);
        }

        // POST: /Admin/Users/Lock/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> Lock(string id) => ChangeUserAsync(id, protectSelf: true, async (user, admin) =>
        {
            await _userManager.SetLockoutEnabledAsync(user, true);
            await _userManager.SetLockoutEndDateAsync(user, AdminLockEnd);
            await SignOutEverywhereAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminLockedAccount, actor: admin);
            return _t["The account was locked and signed out of all devices."];
        });

        // POST: /Admin/Users/Unlock/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> Unlock(string id) => ChangeUserAsync(id, protectSelf: false, async (user, admin) =>
        {
            await _userManager.SetLockoutEndDateAsync(user, null);
            await _userManager.ResetAccessFailedCountAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminUnlockedAccount, actor: admin);
            return _t["The account was unlocked."];
        });

        // POST: /Admin/Users/SignOut/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> SignOutUser(string id) => ChangeUserAsync(id, protectSelf: true, async (user, admin) =>
        {
            await SignOutEverywhereAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminSignedOutUser, actor: admin);
            return _t["The user was signed out of all devices."];
        });

        // POST: /Admin/Users/ResetTwoFactor/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> ResetTwoFactor(string id) => ChangeUserAsync(id, protectSelf: true, async (user, admin) =>
        {
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
            await SignOutEverywhereAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminResetTwoFactor, actor: admin);
            return _t["Two-factor authentication was turned off and the authenticator key was reset."];
        });

        // POST: /Admin/Users/ConfirmEmail/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> ConfirmEmail(string id) => ChangeUserAsync(id, protectSelf: false, async (user, admin) =>
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _userManager.ConfirmEmailAsync(user, token);
            await _adminBootstrapper.EnsureAdminAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminConfirmedEmail, actor: admin);
            return _t["The email address was marked as confirmed."];
        });

        // POST: /Admin/Users/UpdateRoles/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> UpdateRoles(string id, string[]? roles)
        {
            var user = await _userManager.FindByIdAsync(id);
            var admin = await _userManager.GetUserAsync(User);
            if (user == null || admin == null)
                return NotFound();

            var wanted = (roles ?? []).Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var current = await _userManager.GetRolesAsync(user);
            var removingAdmin = current.Contains(AdminBootstrapper.AdminRole) && !wanted.Contains(AdminBootstrapper.AdminRole, StringComparer.OrdinalIgnoreCase);

            if (removingAdmin && user.Id == admin.Id)
            {
                this.StatusError(_t["You can't remove the Admin role from yourself."]);
                return RedirectToAction(nameof(Details), new { id });
            }
            if (removingAdmin && (await _userManager.GetUsersInRoleAsync(AdminBootstrapper.AdminRole)).Count <= 1)
            {
                this.StatusError(_t["There must always be at least one administrator."]);
                return RedirectToAction(nameof(Details), new { id });
            }

            var existingRoles = await _roleManager.Roles.Select(r => r.Name!).ToListAsync();
            var toAdd = wanted.Where(r => existingRoles.Contains(r) && !current.Contains(r)).ToList();
            var toRemove = current.Where(r => !wanted.Contains(r, StringComparer.OrdinalIgnoreCase)).ToList();
            if (toAdd.Count > 0) await _userManager.AddToRolesAsync(user, toAdd);
            if (toRemove.Count > 0) await _userManager.RemoveFromRolesAsync(user, toRemove);

            if (toAdd.Count + toRemove.Count > 0)
            {
                // Role changes take effect at the user's next security stamp check
                await _userManager.UpdateSecurityStampAsync(user);
                var details = string.Join(", ", toAdd.Select(r => "+" + r).Concat(toRemove.Select(r => "-" + r)));
                await _notifier.NotifyAsync(user, SecurityEvent.AdminChangedRoles, actor: admin, details: details);
            }

            this.StatusSuccess(_t["The roles were updated."]);
            return RedirectToAction(nameof(Details), new { id });
        }

        // POST: /Admin/Users/Delete/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public async Task<IActionResult> Delete(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            var admin = await _userManager.GetUserAsync(User);
            if (user == null || admin == null)
                return NotFound();

            if (user.Id == admin.Id)
            {
                this.StatusError(_t["You can't delete your own account here. Use Manage account > Personal data."]);
                return RedirectToAction(nameof(Details), new { id });
            }
            if (await _userManager.IsInRoleAsync(user, AdminBootstrapper.AdminRole)
                && (await _userManager.GetUsersInRoleAsync(AdminBootstrapper.AdminRole)).Count <= 1)
            {
                this.StatusError(_t["There must always be at least one administrator."]);
                return RedirectToAction(nameof(Details), new { id });
            }

            await _sessions.RevokeAllAsync(user.Id);
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                this.StatusError(_t["The account could not be deleted."]);
                return RedirectToAction(nameof(Details), new { id });
            }

            await _notifier.NotifyAsync(user, SecurityEvent.AdminDeletedAccount, actor: admin);
            _logger.LogWarning("Administrator {AdminId} deleted user {UserId}.", admin.Id, user.Id);
            this.StatusSuccess(_t["The account {0} was deleted.", user.Email ?? user.Id]);
            return RedirectToAction(nameof(Index));
        }

        private async Task SignOutEverywhereAsync(IdentityUser user)
        {
            await _userManager.UpdateSecurityStampAsync(user);
            await _sessions.RevokeAllAsync(user.Id);
        }

        /// <summary>Loads the target user and the acting admin, applies the change, shows the result.</summary>
        private async Task<IActionResult> ChangeUserAsync(string id, bool protectSelf, Func<IdentityUser, IdentityUser, Task<string>> change)
        {
            var user = await _userManager.FindByIdAsync(id);
            var admin = await _userManager.GetUserAsync(User);
            if (user == null || admin == null)
                return NotFound();

            if (protectSelf && user.Id == admin.Id)
            {
                this.StatusError(_t["You can't do this to your own account."]);
                return RedirectToAction(nameof(Details), new { id });
            }

            this.StatusSuccess(await change(user, admin));
            return RedirectToAction(nameof(Details), new { id });
        }
    }
}
