using identity.Services;

namespace identity.ViewModels;

public class ProfileViewModel
{
    public string Fullname { get; set; }
    
    [CustomEmail]
    public string Email { get; set; }

    [CustomPhone]
    public string Phone { get; set; }
}