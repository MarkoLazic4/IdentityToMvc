using IdentityToMvc.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace IdentityToMvc.Web.Areas.Admin.Controllers
{
    /// <summary>
    /// Common rules for every admin page: Admin role only, the admin's own account must use
    /// 2FA or a passkey, and form posts are rate limited.
    /// </summary>
    [Area("Admin")]
    [Authorize(Roles = AdminBootstrapper.AdminRole)]
    [RequireAdminSecurity]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [TypeFilter(typeof(RefreshSessionOnSecurityStampChangeFilter))]
    public abstract class AdminControllerBase : Controller
    {
        protected const int PageSize = 25;
    }
}
