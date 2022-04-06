using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using identity.Attributes;
using Microsoft.AspNetCore.Authentication;

namespace identity.ViewModels;

public class RegisterViewModel
{
    [CustomRequired]
    [CustomDisplayName("Full Name")]
    [CustomMinLength(5)]
    [CustomMaxLength(64)]
    public string Fullname { get; set; }
    
    [CustomEmail]
    [CustomRequired]
    [CustomMaxLength(64)]
    public string Email { get; set; }

    [CustomRequired]
    [CustomPhone]
    [CustomMaxLength(32)]
    public string Phone { get; set; }

    [DataType(DataType.Password)]
    [CustomRequired]
    [CustomMinLength(6)]
    [CustomMaxLength(128)]
    public string Password { get; set; }

    [CustomDisplayName("Confirm Password")]
    [DataType(DataType.Password)]
    [CustomCompare(nameof(Password))]
    public string ConfirmPassword { get; set; }
    
    public string ReturnUrl { get; set; }

    public IEnumerable<AuthenticationScheme> ExternalProviders { get; internal set; }

    public string ErrorMessage { get; set; }

    public bool IsExternal { get; set; }
}