using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace identity.ViewModels;

public class RegisterViewModel
{
    public string Fullname { get; set; }
    
    [EmailAddress]
    [Required]
    public string Email { get; set; }

    [Phone]
    public string Phone { get; set; }

    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Compare(nameof(Password))]
    public string ConfirmPassword { get; set; }
    
    public string ReturnUrl { get; set; }

    public IEnumerable<AuthenticationScheme> ExternalProviders { get; internal set; }

    public string ErrorMessage { get; set; }

    public bool IsExternal { get; set; }
}