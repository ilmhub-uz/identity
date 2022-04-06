using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using identity.Attributes;

namespace identity.ViewModels;
public class ResetPasswordViewModel
{
    [CustomRequired]
    public string UserId { get; set; }
    
    [CustomRequired]
    public string Token { get; set; }
    
    [CustomRequired]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    
    [CustomRequired]
    [DataType(DataType.Password)]
    [CustomDisplayName("Confirm Password")]
    [CustomCompare(nameof(Password))]
    public string ConfirmPassword { get; set; }
}