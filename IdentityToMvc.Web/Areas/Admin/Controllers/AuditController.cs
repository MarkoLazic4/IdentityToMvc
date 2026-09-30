using IdentityToMvc.Web.Areas.Admin.ViewModels;
using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityToMvc.Web.Areas.Admin.Controllers
{
    public class AuditController : AdminControllerBase
    {
        private const int AuditPageSize = 50;
        private readonly ApplicationDbContext _db;

        public AuditController(ApplicationDbContext db)
        {
            _db = db;
        }

        // GET: /Admin/Audit?q=...&eventType=...&page=1
        [HttpGet]
        public async Task<IActionResult> Index(string? q, string? eventType, int page = 1)
        {
            var query = _db.SecurityEvents.AsQueryable();
            if (!string.IsNullOrWhiteSpace(q))
            {
                var term = q.Trim();
                query = query.Where(e => (e.UserEmail != null && e.UserEmail.Contains(term))
                    || (e.IpAddress != null && e.IpAddress.Contains(term))
                    || (e.ActorEmail != null && e.ActorEmail.Contains(term)));
            }
            if (!string.IsNullOrWhiteSpace(eventType) && Enum.IsDefined(typeof(SecurityEvent), eventType))
            {
                query = query.Where(e => e.Event == eventType);
            }

            var total = await query.CountAsync();
            var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)AuditPageSize));
            page = Math.Clamp(page, 1, totalPages);

            return View(new AuditViewModel
            {
                Query = q,
                EventType = eventType,
                Page = page,
                TotalPages = totalPages,
                EventTypes = Enum.GetNames<SecurityEvent>(),
                Events = await query.OrderByDescending(e => e.CreatedAt)
                    .Skip((page - 1) * AuditPageSize).Take(AuditPageSize).ToListAsync()
            });
        }
    }
}
