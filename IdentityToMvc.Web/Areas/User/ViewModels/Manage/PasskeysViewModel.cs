namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class PasskeysViewModel
    {
        public IList<PasskeyItem> Passkeys { get; set; } = new List<PasskeyItem>();
        public int MaxPasskeys { get; set; }

        public class PasskeyItem
        {
            /// <summary>Base64Url encoded credential id.</summary>
            public string Id { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;
            public DateTimeOffset CreatedAt { get; set; }
            public bool IsBackedUp { get; set; }
        }
    }
}
