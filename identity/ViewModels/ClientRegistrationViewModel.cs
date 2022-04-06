using System.ComponentModel.DataAnnotations;
using IdentityModel;
using Newtonsoft.Json;

namespace identity.ViewModels;

public class ClientRegistrationViewModel
{
    public string ClientName { get; set; }
    public string ClientUri { get; set; }
    public IEnumerable<string> GrantTypes { get; set; }
    public IEnumerable<string> RedirectUris { get; set; } = new List<string>();
    public string Scope { get; set; } = "openid profile email";
    public string ErrorMessage { get; set; }
}