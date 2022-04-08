using System.ComponentModel.DataAnnotations;
using identity.Attributes;

namespace identity.ViewModels;

public class ProfileViewModel
{
    public string Fullname { get; set; }
    
    [EmailAddress]
    public string Email { get; set; }

    [CustomPhone]
    public string Phone { get; set; }
}