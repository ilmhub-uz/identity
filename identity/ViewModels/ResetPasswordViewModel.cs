using System.ComponentModel.DataAnnotations;
namespace identity.ViewModels;
public class ResetPasswordViewModel
{
    [Required]
    public string UserId { get; set; }
    
    [Required]
    public string Token { get; set; }
    
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    
    [Required]
    [DataType(DataType.Password)]
    [Compare(nameof(Password))]
    public string ConfirmPassword { get; set; }
}