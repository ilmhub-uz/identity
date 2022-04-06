using identity.ViewModels;
using IdentityModel;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Entities;
using Microsoft.AspNetCore.Mvc;

namespace identity.Controllers;

public class ClientController : Controller
{
    private readonly ConfigurationDbContext _context;

    public ClientController(ConfigurationDbContext context)
    {
        _context = context;
    }

    // POST: connect/register
    [HttpPost]
    public async Task<IActionResult> Register(ClientRegistrationViewModel model)
    {
        if (!Request.IsHttps)
        {
            return BadRequest("HTTPS is required at this endpoint.");
        }

        if (model.GrantTypes == null)
        {
            model.GrantTypes = new List<string> { OidcConstants.GrantTypes.AuthorizationCode };
        }

        if (model.GrantTypes.Any(x => x == OidcConstants.GrantTypes.Implicit) || model.GrantTypes.Any(x => x == OidcConstants.GrantTypes.AuthorizationCode))
        {
            if (!model.RedirectUris.Any())
            {
                return BadRequest("A redirect URI is required for the supplied grant type.");
            }

            if (model.RedirectUris.Any(redirectUri => !Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute)))
            {
                return BadRequest("One or more of the redirect URIs are invalid.");
            }
        }

        var response = new ClientRegistrationResponseViewModel
        {
            ClientId = Guid.NewGuid().ToString(),
            ClientSecret = GenerateSecret(32),
            ClientName = model.ClientName,
            ClientUri = model.ClientUri,
            GrantTypes = model.GrantTypes,
            RedirectUris = model.RedirectUris,
            Scope = model.Scope
        };

        var client = new Client
        {
            ClientId = response.ClientId,
            ClientName = response.ClientName,
            ClientSecrets = new List<ClientSecret>(),
            ClientUri = model.ClientUri,
            AllowedGrantTypes = new List<ClientGrantType>(),
            AllowedScopes = new List<ClientScope>(),
            RedirectUris = new List<ClientRedirectUri>()
        };
        
        client.ClientSecrets.Add(new ClientSecret
        {
            Value = response.ClientSecret, 
            Client = client
        });

        foreach (var scope in model.Scope.Split())
        {
            client.AllowedScopes.Add(new ClientScope
            {
                Scope = scope,
                Client = client
            });
        }

        foreach (var grantType in model.GrantTypes)
        {
            client.AllowedGrantTypes.Add(new ClientGrantType { Client = client, GrantType = grantType });
        }

        foreach (var redirectUri in model.RedirectUris)
        {
            client.RedirectUris.Add(new ClientRedirectUri { Client = client, RedirectUri = redirectUri });
        }

        _context.Clients.Add(client);
        
        await _context.SaveChangesAsync();

        return Ok(response);
    }

    private string GenerateSecret(int v)
    {
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-0123456789";
        var stringChars = new char[v];
        var random = new Random();

        for (int i = 0; i < stringChars.Length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        return new string(stringChars);
    }
}