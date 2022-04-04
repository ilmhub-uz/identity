using System.ComponentModel.DataAnnotations;

namespace identity.ViewModels;

public class ProfileViewModel
{
    public string Fullname { get; set; }
    
    [EmailAddress]
    public string Email { get; set; }

    [Phone]
    public string Phone { get; set; }
}