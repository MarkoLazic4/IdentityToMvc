using IdentityToMvc.Web.Settings;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

namespace IdentityToMvc.Web.Services
{
    public class EmailService : IEmailService
    {
        private readonly IOptions<SmtpSettings> _smtpSetting;

        public EmailService(IOptions<SmtpSettings> smtpSetting)
        {
            _smtpSetting = smtpSetting;
        }

        public async Task SendEmailAsync(string fromAddress, string toAddress, string subject, string message)
        {
            using var mailMessage = new MailMessage(fromAddress, toAddress, subject, message)
            {
                IsBodyHtml = true
            };

            using (var emailClient = new SmtpClient(_smtpSetting.Value.Host, _smtpSetting.Value.Port))
            {
                emailClient.EnableSsl = _smtpSetting.Value.EnableSsl;
                emailClient.Credentials = new NetworkCredential(_smtpSetting.Value.Username, _smtpSetting.Value.Password);

                await emailClient.SendMailAsync(mailMessage);
            }
        }
    }
}
