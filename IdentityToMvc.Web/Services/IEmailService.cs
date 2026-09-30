namespace IdentityToMvc.Web.Services
{
    public interface IEmailService
    {
        /// <summary>
        /// Sends an HTML email from the configured sender address.
        /// Returns <c>false</c> (and logs the error) when the message could not be sent.
        /// </summary>
        Task<bool> SendEmailAsync(string toAddress, string subject, string htmlMessage);
    }
}
