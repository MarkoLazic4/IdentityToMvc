using IdentityToMvc.Web.Areas.Admin.ViewModels;
using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityToMvc.Web.Areas.Admin.Controllers
{
    public class DashboardController : AdminControllerBase
    {
        private readonly ApplicationDbContext _db;

        public DashboardController(ApplicationDbContext db)
        {
            _db = db;
        }

        // GET: /Admin/Dashboard
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var now = DateTime.UtcNow;
            var dayAgo = now.AddDays(-1);
            var hourAgo = now.AddHours(-1);

            // LockoutEnd is a DateTimeOffset, which not every database provider can compare in SQL
            var lockoutEnds = await _db.Users.Where(u => u.LockoutEnd != null).Select(u => u.LockoutEnd).ToListAsync();

            var viewModel = new DashboardViewModel
            {
                TotalUsers = await _db.Users.CountAsync(),
                ConfirmedUsers = await _db.Users.CountAsync(u => u.EmailConfirmed),
                TwoFactorUsers = await _db.Users.CountAsync(u => u.TwoFactorEnabled),
                PasskeyUsers = await _db.Set<IdentityUserPasskey<string>>().Select(p => p.UserId).Distinct().CountAsync(),
                LockedUsers = lockoutEnds.Count(end => end > DateTimeOffset.UtcNow),
                ActiveSessions = await _db.UserSessions.CountAsync(s => s.RevokedAt == null && s.LastSeenAt >= hourAgo),
                SignIns24h = await CountEventsAsync(SecurityEvent.SignedIn, dayAgo),
                FailedLogins24h = await CountEventsAsync(SecurityEvent.LoginFailed, dayAgo),
                Lockouts24h = await CountEventsAsync(SecurityEvent.AccountLockedOut, dayAgo),
                RecentEvents = await _db.SecurityEvents.OrderByDescending(e => e.CreatedAt).Take(12).ToListAsync()
            };
            return View(viewModel);
        }

        private Task<int> CountEventsAsync(SecurityEvent securityEvent, DateTime since)
        {
            var name = securityEvent.ToString();
            return _db.SecurityEvents.CountAsync(e => e.Event == name && e.CreatedAt >= since);
        }
    }
}
