namespace GymmrWebApi.Models
{
    public class Photo
    {
        public int PhotoId { get; set; }
        public string Url { get; set; } = string.Empty;
        public bool IsMain { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
}
