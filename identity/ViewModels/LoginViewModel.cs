using System.ComponentModel.DataAnnotations;

namespace identity.ViewModels;

public class LoginViewModel
{
    [EmailAddress]
    public string Email { get; set; }

    [DataType(DataType.Password)]
    public string Password { get; set; }
    
    [Compare(nameof(Password), ErrorMessage = "Confirm password doesnt match.")]
    public string ConfirmPassword { get; set; }

    public string ReturnUrl { get; set; }
}