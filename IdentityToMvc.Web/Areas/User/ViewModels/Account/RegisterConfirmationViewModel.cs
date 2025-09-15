namespace IdentityToMvc.Web.Areas.User.ViewModels.Account
{
    public class RegisterConfirmationViewModel
    {
        public string Email { get; set; } = string.Empty;
        public bool DisplayConfirmAccountLink { get; set; }
        public string? EmailConfirmationUrl { get; set; }
    }
}
