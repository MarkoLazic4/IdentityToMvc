using IdentityToMvc.Web.Settings;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace IdentityToMvc.Web.Services
{
    public class EmailService : IEmailService
    {
        private readonly IOptions<SmtpSettings> _smtpSetting;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<SmtpSettings> smtpSetting, ILogger<EmailService> logger)
        {
            _smtpSetting = smtpSetting;
            _logger = logger;
        }

        public async Task<bool> SendEmailAsync(string toAddress, string subject, string htmlMessage)
        {
            var settings = _smtpSetting.Value;

            try
            {
                using var mailMessage = new MailMessage
                {
                    From = new MailAddress(settings.From, settings.FromName),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toAddress);

                using var emailClient = new SmtpClient(settings.Host, settings.Port)
                {
                    EnableSsl = settings.EnableSsl,
                    Credentials = new NetworkCredential(settings.Username, settings.Password)
                };

                await emailClient.SendMailAsync(mailMessage);
                return true;
            }
            catch (Exception ex) when (ex is SmtpException or InvalidOperationException or FormatException)
            {
                _logger.LogError(ex, "Failed to send email '{Subject}' via {Host}:{Port}.", subject, settings.Host, settings.Port);
                return false;
            }
        }
    }
}
