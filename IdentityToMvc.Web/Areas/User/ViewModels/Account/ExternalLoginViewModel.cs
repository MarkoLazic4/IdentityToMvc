using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Account
{
    public class ExternalLoginViewModel
    {
        public InputModel Input { get; set; } = new();
        public string ProviderDisplayName { get; set; } = string.Empty;
        public string? ReturnUrl { get; set; } = null;


        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;
        }
    }
}
