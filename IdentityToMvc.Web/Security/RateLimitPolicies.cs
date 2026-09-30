using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Per-IP rate limits for the account endpoints. They sit in front of Identity's per-account
    /// lockout: lockout protects a single account, rate limiting protects against one client
    /// spraying many accounts or flooding the email endpoints.
    /// </summary>
    public static class RateLimitPolicies
    {
        /// <summary>Login, 2FA, password changes and other sensitive form posts.</summary>
        public const string Auth = "auth";

        /// <summary>Endpoints that send an email (register, forgot password, resend confirmation).</summary>
        public const string Email = "email";

        public static IServiceCollection AddAccountRateLimiting(this IServiceCollection services)
        {
            services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.OnRejected = (context, _) =>
                {
                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    {
                        context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
                    }
                    context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                        .CreateLogger("IdentityToMvc.Security.RateLimiting")
                        .LogWarning("Rate limit hit for {Path} from {Ip}.", context.HttpContext.Request.Path,
                            context.HttpContext.Connection.RemoteIpAddress);
                    return ValueTask.CompletedTask;
                };

                // Only POSTs are limited; viewing the forms stays free.
                options.AddPolicy(Auth, context => HttpMethods.IsPost(context.Request.Method)
                    ? RateLimitPartition.GetSlidingWindowLimiter(ClientKey(context), _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = 20,
                        Window = TimeSpan.FromMinutes(1),
                        SegmentsPerWindow = 6,
                        QueueLimit = 0
                    })
                    : RateLimitPartition.GetNoLimiter("get"));

                options.AddPolicy(Email, context => HttpMethods.IsPost(context.Request.Method)
                    ? RateLimitPartition.GetFixedWindowLimiter(ClientKey(context), _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(10),
                        QueueLimit = 0
                    })
                    : RateLimitPartition.GetNoLimiter("get"));
            });

            return services;
        }

        /// <summary>
        /// IPv4 clients are limited per address. IPv6 clients usually control a whole /64 network
        /// (18 quintillion addresses), so they are limited per /64 - otherwise changing the address
        /// would reset the limit.
        /// </summary>
        internal static string ClientKey(HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress;
            if (ip == null)
                return "unknown";
            if (ip.IsIPv4MappedToIPv6)
                ip = ip.MapToIPv4();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var bytes = ip.GetAddressBytes();
                return Convert.ToHexString(bytes, 0, 8) + "::/64";
            }
            return ip.ToString();
        }
    }
}
