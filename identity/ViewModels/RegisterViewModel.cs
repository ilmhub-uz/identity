using System.ComponentModel.DataAnnotations;

namespace identity.ViewModels;

public class RegisterViewModel
{
    public string Fullname { get; set; }
    
    [EmailAddress]
    public string Email { get; set; }

    [Phone]
    public string Phone { get; set; }

    [DataType(DataType.Password)]
    public string Password { get; set; }
    public string ReturnUrl { get; set; }
}