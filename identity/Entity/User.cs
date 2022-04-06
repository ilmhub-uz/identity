using Microsoft.AspNetCore.Identity;

namespace identity.Entity;

public class User : IdentityUser
{
    public string Fullname { get; set; }
    public string Bio { get; set; }
    public DateTimeOffset Birthdate { get; set; }
    public virtual ICollection<IdentityRole> Roles { get; set; }
    public bool IsExternal { get; set; }
    public string ExternalProvider { get; set; }
}