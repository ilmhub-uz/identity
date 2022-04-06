using System.ComponentModel.DataAnnotations;
using identity.Attributes;
using Microsoft.AspNetCore.Authentication;

namespace identity.ViewModels;

public class LoginViewModel
{
    [CustomEmail]
    [CustomRequired]
    [CustomMaxLength(64)]
    public string Email { get; set; }

    [DataType(DataType.Password)]
    [CustomRequired]
    [CustomMinLength(6)]
    [CustomMaxLength(128)]
    public string Password { get; set; }
    
    // [CustomCompare(nameof(Password))]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }

    public string ReturnUrl { get; set; }
    public IEnumerable<AuthenticationScheme> ExternalProviders { get; internal set; }
    public IEnumerable<string> ErrorMessages { get; set; }
    
    
}