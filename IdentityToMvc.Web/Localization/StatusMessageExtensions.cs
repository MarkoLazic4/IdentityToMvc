using Microsoft.AspNetCore.Mvc;

namespace IdentityToMvc.Web.Localization
{
    /// <summary>
    /// One-time messages shown after a redirect ("Your password has been changed.").
    /// The error flag is stored separately so the message itself can be translated.
    /// </summary>
    public static class StatusMessageExtensions
    {
        public const string MessageKey = "StatusMessage";
        public const string IsErrorKey = "StatusIsError";

        public static void StatusSuccess(this Controller controller, string message)
        {
            controller.TempData[MessageKey] = message;
            controller.TempData[IsErrorKey] = false;
        }

        public static void StatusError(this Controller controller, string message)
        {
            controller.TempData[MessageKey] = message;
            controller.TempData[IsErrorKey] = true;
        }
    }
}
