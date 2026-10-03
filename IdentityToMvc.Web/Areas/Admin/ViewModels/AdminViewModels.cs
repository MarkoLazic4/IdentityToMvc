using IdentityToMvc.Web.Data;

namespace IdentityToMvc.Web.Areas.Admin.ViewModels
{
    public class DashboardViewModel
    {
        public int TotalUsers { get; set; }
        public int ConfirmedUsers { get; set; }
        public int TwoFactorUsers { get; set; }
        public int PasskeyUsers { get; set; }
        public int LockedUsers { get; set; }
        public int ActiveSessions { get; set; }
        public int SignIns24h { get; set; }
        public int FailedLogins24h { get; set; }
        public int Lockouts24h { get; set; }
        public IList<SecurityEventRecord> RecentEvents { get; set; } = new List<SecurityEventRecord>();

        public int Percent(int value) => TotalUsers == 0 ? 0 : (int)Math.Round(100.0 * value / TotalUsers);
    }

    public class UserListViewModel
    {
        public string? Query { get; set; }
        public int Page { get; set; } = 1;
        public int TotalPages { get; set; }
        public int TotalCount { get; set; }
        public IList<UserRow> Users { get; set; } = new List<UserRow>();

        public class UserRow
        {
            public string Id { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public bool EmailConfirmed { get; set; }
            public bool TwoFactorEnabled { get; set; }
            public bool IsLocked { get; set; }
            public bool IsAdminLock { get; set; }
            public IList<string> Roles { get; set; } = new List<string>();
            public DateTime? LastActive { get; set; }
        }
    }

    public class UserDetailsViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public bool HasPassword { get; set; }
        public int PasskeyCount { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        public bool IsLocked { get; set; }
        public bool IsAdminLock { get; set; }
        public bool IsCurrentUser { get; set; }
        public IList<string> ExternalLogins { get; set; } = new List<string>();
        public IList<string> Roles { get; set; } = new List<string>();
        public IList<string> AllRoles { get; set; } = new List<string>();
        public IList<UserSession> Sessions { get; set; } = new List<UserSession>();
        public IList<SecurityEventRecord> Events { get; set; } = new List<SecurityEventRecord>();
    }

    public class RolesViewModel
    {
        public IList<RoleRow> Roles { get; set; } = new List<RoleRow>();
        public string? NewRoleName { get; set; }

        public class RoleRow
        {
            public string Name { get; set; } = string.Empty;
            public int UserCount { get; set; }
            public bool IsProtected { get; set; }
        }
    }

    public class AuditViewModel
    {
        public string? Query { get; set; }
        public string? EventType { get; set; }
        public int Page { get; set; } = 1;
        public int TotalPages { get; set; }
        public IList<SecurityEventRecord> Events { get; set; } = new List<SecurityEventRecord>();
        public IList<string> EventTypes { get; set; } = new List<string>();
    }
}
