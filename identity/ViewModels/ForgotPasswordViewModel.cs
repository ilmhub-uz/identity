using identity.Services;

namespace identity.ViewModels;

public class ForgotPasswordViewModel
{
    [CustomEmail]
    [CustomRequired]
    [CustomMaxLength(64)]
    public string Email { get; set; }
}