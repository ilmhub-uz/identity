using IdentityModel;
using Newtonsoft.Json;

namespace identity.ViewModels;
public class ClientRegistrationResponseViewModel : ClientRegistrationViewModel
{
    [JsonProperty(OidcConstants.RegistrationResponse.ClientId)]
    public string ClientId { get; set; }

    [JsonProperty(OidcConstants.RegistrationResponse.ClientSecret)]
    public string ClientSecret { get; set; }
}