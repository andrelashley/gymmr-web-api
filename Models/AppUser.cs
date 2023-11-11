using Microsoft.AspNetCore.Identity;

namespace GymmrWebApi.Models
{
    public class AppUser : IdentityUser
    {
        public string? FirstName { get; set; }
    }
}
