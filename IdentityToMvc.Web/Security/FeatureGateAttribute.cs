using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Returns 404 for actions of a feature that is switched off in the "Security" settings,
    /// so a disabled feature can't be reached even by typing its address.
    /// </summary>
    public sealed class FeatureGateAttribute : Attribute, IAsyncActionFilter
    {
        private readonly SecurityFeature _feature;

        public FeatureGateAttribute(SecurityFeature feature)
        {
            _feature = feature;
        }

        public Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptionsMonitor<SecurityOptions>>().CurrentValue;
            if (!options.IsEnabled(_feature))
            {
                context.Result = new NotFoundResult();
                return Task.CompletedTask;
            }

            return next();
        }
    }
}
