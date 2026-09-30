namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class DevicesViewModel
    {
        public IList<DeviceItem> Devices { get; set; } = new List<DeviceItem>();

        public class DeviceItem
        {
            public string Id { get; set; } = string.Empty;
            public string Device { get; set; } = string.Empty;
            public string? IpAddress { get; set; }
            public DateTime CreatedAt { get; set; }
            public DateTime LastSeenAt { get; set; }
            public bool IsCurrent { get; set; }
        }
    }
}
