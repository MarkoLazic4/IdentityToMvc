namespace IdentityToMvc.Web.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(string fromAddress, string toAddress, string subject, string message);
    }
}
