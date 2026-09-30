namespace IdentityToMvc.Web.Settings
{
    public class SmtpSettings
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public bool EnableSsl { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string From { get; set; } = "identitytomvc@gmail.com";
        public string FromName { get; set; } = "IdentityToMvc";
    }
}
