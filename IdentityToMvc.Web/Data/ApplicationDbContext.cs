using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityToMvc.Web.Data
{
    public class ApplicationDbContext : IdentityDbContext, IDataProtectionKeyContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        /// <summary>
        /// Data Protection keys (used for auth cookies, antiforgery and Identity tokens) are stored
        /// in the database so they survive restarts and are shared between app instances.
        /// </summary>
        public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

        /// <summary>Security audit log (see SecurityNotifier).</summary>
        public DbSet<SecurityEventRecord> SecurityEvents => Set<SecurityEventRecord>();

        /// <summary>Signed-in devices (see SessionService).</summary>
        public DbSet<UserSession> UserSessions => Set<UserSession>();

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<SecurityEventRecord>(entity =>
            {
                entity.ToTable("SecurityEvents");
                entity.Property(e => e.UserId).HasMaxLength(450);
                entity.Property(e => e.UserEmail).HasMaxLength(256);
                entity.Property(e => e.Event).HasMaxLength(64).IsRequired();
                entity.Property(e => e.IpAddress).HasMaxLength(64);
                entity.Property(e => e.Device).HasMaxLength(128);
                entity.Property(e => e.ActorUserId).HasMaxLength(450);
                entity.Property(e => e.ActorEmail).HasMaxLength(256);
                entity.Property(e => e.Details).HasMaxLength(512);
                entity.HasIndex(e => new { e.UserId, e.CreatedAt });
                entity.HasIndex(e => e.CreatedAt);
            });

            builder.Entity<UserSession>(entity =>
            {
                entity.ToTable("UserSessions");
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Id).HasMaxLength(64);
                entity.Property(e => e.UserId).HasMaxLength(450).IsRequired();
                entity.Property(e => e.IpAddress).HasMaxLength(64);
                entity.Property(e => e.Device).HasMaxLength(128);
                entity.HasIndex(e => e.UserId);
            });
        }
    }
}
