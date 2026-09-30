using System.Threading.Channels;

namespace IdentityToMvc.Web.Services
{
    public sealed record QueuedEmail(string ToAddress, string Subject, string HtmlMessage);

    /// <summary>
    /// Queues emails to be sent in the background.
    /// Anonymous endpoints (register, forgot password, resend confirmation) use the queue so the
    /// response time is the same whether or not an email was sent - otherwise timing would reveal
    /// which addresses have an account. It also keeps a slow SMTP server from blocking requests.
    /// </summary>
    public interface IEmailQueue
    {
        void Enqueue(string toAddress, string subject, string htmlMessage);
    }

    public sealed class EmailQueue : IEmailQueue
    {
        private readonly Channel<QueuedEmail> _channel = Channel.CreateBounded<QueuedEmail>(
            new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

        public ChannelReader<QueuedEmail> Reader => _channel.Reader;

        public void Enqueue(string toAddress, string subject, string htmlMessage) =>
            _channel.Writer.TryWrite(new QueuedEmail(toAddress, subject, htmlMessage));
    }

    public sealed class EmailQueueWorker : BackgroundService
    {
        private readonly EmailQueue _queue;
        private readonly IEmailService _emailService;

        public EmailQueueWorker(EmailQueue queue, IEmailService emailService)
        {
            _queue = queue;
            _emailService = emailService;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var email in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                // EmailService logs failures itself and never throws for SMTP errors
                await _emailService.SendEmailAsync(email.ToAddress, email.Subject, email.HtmlMessage);
            }
        }
    }
}
