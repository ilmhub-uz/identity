using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace identity.ViewModels;

public class LoginViewModel
{
    [EmailAddress(ErrorMessage = "Invalid Email Address")]
    [Required(ErrorMessage = "Email is required")]
    public string Email { get; set; }

    [DataType(DataType.Password)]
    [MinLength(6)]
    public string Password { get; set; }
    
    [Compare(nameof(Password), ErrorMessage = "Confirm password doesnt match.")]
    public string ConfirmPassword { get; set; }

    public string ReturnUrl { get; set; }
    public IEnumerable<AuthenticationScheme> ExternalProviders { get; internal set; }
}