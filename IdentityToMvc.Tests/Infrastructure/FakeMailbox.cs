using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using IdentityToMvc.Web.Services;

namespace IdentityToMvc.Tests.Infrastructure;

public sealed record SentEmail(string To, string Subject, string Html)
{
    /// <summary>The first link in the message whose URL contains <paramref name="path"/> (HTML-decoded).</summary>
    public string Link(string path)
    {
        foreach (Match match in Regex.Matches(Html, "href=\"([^\"]+)\""))
        {
            var url = WebUtility.HtmlDecode(match.Groups[1].Value);
            if (url.Contains(path, StringComparison.OrdinalIgnoreCase))
                return url;
        }
        throw new InvalidOperationException($"No link containing '{path}' in email '{Subject}'.");
    }
}

/// <summary>Collects the emails the app sends (they go through the background email queue).</summary>
public sealed class FakeMailbox : IEmailService
{
    private readonly ConcurrentQueue<SentEmail> _sent = new();

    public IReadOnlyList<SentEmail> All => _sent.ToList();

    public Task<bool> SendEmailAsync(string toAddress, string subject, string htmlMessage)
    {
        _sent.Enqueue(new SentEmail(toAddress, subject, htmlMessage));
        return Task.FromResult(true);
    }

    public IReadOnlyList<SentEmail> For(string to) =>
        _sent.Where(e => string.Equals(e.To, to, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>Waits until <paramref name="to"/> has received more than <paramref name="alreadyReceived"/> emails.</summary>
    public async Task<SentEmail> WaitForAsync(string to, int alreadyReceived = 0, Func<SentEmail, bool>? match = null)
    {
        for (var i = 0; i < 100; i++)
        {
            var found = For(to).Skip(alreadyReceived).FirstOrDefault(e => match == null || match(e));
            if (found != null) return found;
            await Task.Delay(50);
        }
        throw new TimeoutException($"No email for {to} arrived.");
    }

    /// <summary>Gives the queue a moment to deliver, then returns the emails <paramref name="to"/> received.</summary>
    public async Task<IReadOnlyList<SentEmail>> SettleAsync(string to)
    {
        await Task.Delay(300);
        return For(to);
    }
}
