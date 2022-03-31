using System.ComponentModel.DataAnnotations;
namespace identity.ViewModels;

public class ForgotPasswordViewModel
{
    [EmailAddress]
    public string Email { get; set; }
}