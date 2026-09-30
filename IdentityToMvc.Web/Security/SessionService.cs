using System.Security.Claims;
using System.Security.Cryptography;
using IdentityToMvc.Web.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Tracks every signed-in device as a row in UserSessions. The auth cookie carries the row id in
    /// the "sid" claim; every request checks (with a short cache) that the session hasn't been
    /// revoked, which makes "sign out this device" take effect immediately.
    /// </summary>
    public sealed class SessionService
    {
        public const string SessionClaimType = "sid";

        private static readonly TimeSpan ActiveCacheDuration = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan LastSeenUpdateInterval = TimeSpan.FromMinutes(5);

        private readonly ApplicationDbContext _db;
        private readonly IMemoryCache _cache;
        private readonly ISecurityNotifier _notifier;
        private readonly UserManager<IdentityUser> _userManager;

        public SessionService(ApplicationDbContext db, IMemoryCache cache, ISecurityNotifier notifier,
            UserManager<IdentityUser> userManager)
        {
            _db = db;
            _cache = cache;
            _notifier = notifier;
            _userManager = userManager;
        }

        public static string? GetSessionId(ClaimsPrincipal? principal) =>
            principal?.FindFirst(SessionClaimType)?.Value;

        /// <summary>Creates a session for a fresh sign-in and records it in the audit log.</summary>
        public async Task<string> StartAsync(HttpContext context, string userId)
        {
            var device = DeviceDescriber.Describe(context.Request.Headers.UserAgent.ToString());
            var now = DateTime.UtcNow;

            // Email the owner when a device signs in that this account has never used before
            // (the very first sign-in, right after registration, is not "new").
            var knownDevices = await _db.UserSessions.Where(s => s.UserId == userId).Select(s => s.Device).Distinct().ToListAsync();
            var isNewDevice = knownDevices.Count > 0 && !knownDevices.Contains(device);

            var session = new UserSession
            {
                Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                UserId = userId,
                CreatedAt = now,
                LastSeenAt = now,
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                Device = device
            };
            _db.UserSessions.Add(session);
            await _db.SaveChangesAsync();

            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                await _notifier.NotifyAsync(user, SecurityEvent.SignedIn, sendEmail: isNewDevice);
            }
            return session.Id;
        }

        /// <summary>False when the session was revoked (signed out from another device or by an admin).</summary>
        public async Task<bool> IsActiveAsync(string sessionId, string userId)
        {
            var active = await _cache.GetOrCreateAsync(CacheKey(sessionId), async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = ActiveCacheDuration;
                return await _db.UserSessions.AnyAsync(s => s.Id == sessionId && s.UserId == userId && s.RevokedAt == null);
            });
            return active;
        }

        /// <summary>Updates "last active" at most every few minutes.</summary>
        public async Task TouchAsync(string sessionId, HttpContext context)
        {
            var throttleKey = "session-touch:" + sessionId;
            if (_cache.TryGetValue(throttleKey, out _))
                return;
            _cache.Set(throttleKey, true, LastSeenUpdateInterval);

            var session = await _db.UserSessions.FindAsync(sessionId);
            if (session != null)
            {
                session.LastSeenAt = DateTime.UtcNow;
                session.IpAddress = context.Connection.RemoteIpAddress?.ToString();
                await _db.SaveChangesAsync();
            }
        }

        public async Task<IReadOnlyList<UserSession>> GetActiveAsync(string userId, TimeSpan maxIdle)
        {
            var cutoff = DateTime.UtcNow - maxIdle;
            return await _db.UserSessions
                .Where(s => s.UserId == userId && s.RevokedAt == null && s.LastSeenAt >= cutoff)
                .OrderByDescending(s => s.LastSeenAt)
                .ToListAsync();
        }

        public async Task<bool> RevokeAsync(string userId, string sessionId)
        {
            var session = await _db.UserSessions.FirstOrDefaultAsync(s => s.Id == sessionId && s.UserId == userId && s.RevokedAt == null);
            if (session == null)
                return false;

            session.RevokedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            _cache.Remove(CacheKey(sessionId));
            return true;
        }

        public async Task RevokeAllAsync(string userId, string? exceptSessionId = null)
        {
            var sessions = await _db.UserSessions
                .Where(s => s.UserId == userId && s.RevokedAt == null && s.Id != exceptSessionId)
                .ToListAsync();
            var now = DateTime.UtcNow;
            foreach (var session in sessions)
            {
                session.RevokedAt = now;
                _cache.Remove(CacheKey(session.Id));
            }
            await _db.SaveChangesAsync();
        }

        private static string CacheKey(string sessionId) => "session-active:" + sessionId;
    }
}
