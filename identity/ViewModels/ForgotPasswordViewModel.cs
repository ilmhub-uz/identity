using System.ComponentModel.DataAnnotations;
using identity.Attributes;

namespace identity.ViewModels;

public class ForgotPasswordViewModel
{
    [CustomEmail]
    [CustomRequired]
    [CustomMaxLength(64)]
    public string Email { get; set; }
}