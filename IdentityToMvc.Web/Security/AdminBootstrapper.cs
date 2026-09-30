using Microsoft.AspNetCore.Identity;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Makes sure the "Admin" role exists and gives it to the accounts listed in
    /// "Admin:Emails" once their email address is confirmed. This is how the first administrator
    /// is created; after that, administrators manage roles in the admin panel.
    /// </summary>
    public sealed class AdminBootstrapper
    {
        public const string AdminRole = "Admin";

        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AdminBootstrapper> _logger;

        public AdminBootstrapper(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, ILogger<AdminBootstrapper> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = logger;
        }

        private IEnumerable<string> ConfiguredEmails =>
            _configuration.GetSection("Admin:Emails").Get<string[]>() ?? [];

        /// <summary>Run at startup: creates the role and promotes configured, confirmed accounts.</summary>
        public async Task InitializeAsync()
        {
            if (!await _roleManager.RoleExistsAsync(AdminRole))
            {
                await _roleManager.CreateAsync(new IdentityRole(AdminRole));
            }

            foreach (var email in ConfiguredEmails)
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    await EnsureAdminAsync(user);
                }
            }
        }

        /// <summary>Called when an account's email gets confirmed.</summary>
        public async Task EnsureAdminAsync(IdentityUser user)
        {
            if (user.Email == null
                || !ConfiguredEmails.Contains(user.Email, StringComparer.OrdinalIgnoreCase)
                || !await _userManager.IsEmailConfirmedAsync(user)
                || await _userManager.IsInRoleAsync(user, AdminRole))
            {
                return;
            }

            if (!await _roleManager.RoleExistsAsync(AdminRole))
            {
                await _roleManager.CreateAsync(new IdentityRole(AdminRole));
            }
            await _userManager.AddToRoleAsync(user, AdminRole);
            _logger.LogInformation("Granted the {Role} role to configured administrator {UserId}.", AdminRole, user.Id);
        }
    }
}
