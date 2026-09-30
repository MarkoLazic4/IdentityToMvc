using IdentityToMvc.Web.Data;
using Microsoft.EntityFrameworkCore;

namespace IdentityToMvc.Web.Services
{
    /// <summary>
    /// Periodically removes old audit entries and ended device sessions, so the database doesn't
    /// keep personal data (IP addresses, devices) longer than needed.
    /// Retention is set with "Security:AuditRetentionDays" (default 365) and
    /// "Security:SessionRetentionDays" (default 30).
    /// </summary>
    public sealed class DataRetentionService : BackgroundService
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DataRetentionService> _logger;

        public DataRetentionService(IServiceScopeFactory scopeFactory, IConfiguration configuration, ILogger<DataRetentionService> logger)
        {
            _scopeFactory = scopeFactory;
            _configuration = configuration;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromHours(12));
            do
            {
                try
                {
                    using var scope = _scopeFactory.CreateScope();
                    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                    var auditCutoff = DateTime.UtcNow.AddDays(-_configuration.GetValue("Security:AuditRetentionDays", 365));
                    var sessionCutoff = DateTime.UtcNow.AddDays(-_configuration.GetValue("Security:SessionRetentionDays", 30));

                    var events = await db.SecurityEvents.Where(e => e.CreatedAt < auditCutoff).ExecuteDeleteAsync(stoppingToken);
                    var sessions = await db.UserSessions.Where(s => s.LastSeenAt < sessionCutoff).ExecuteDeleteAsync(stoppingToken);
                    if (events + sessions > 0)
                    {
                        _logger.LogInformation("Data retention removed {Events} audit entries and {Sessions} sessions.", events, sessions);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Data retention run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
    }
}
