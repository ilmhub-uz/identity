using System.Security.Claims;
using identity.Entity;
using identity.ViewModels;
using IdentityModel;
using IdentityServer4;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace identity.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;

    public AccountController(
        SignInManager<User> signInManager,
        UserManager<User> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    public async Task<IActionResult> Login(string returnUrl)
    {
        var model = new LoginViewModel()
        {
            ReturnUrl = returnUrl,
            ExternalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync()
        };
        return View(model);
    }
    
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
        if(!result.Succeeded)
        {
            model.Email = "Error";
            return View(model);
        }

        return Redirect(model.ReturnUrl ?? "/");
    }

    public IActionResult Register(string returnUrl) => View(new RegisterViewModel() { ReturnUrl = returnUrl });

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if(!ModelState.IsValid)
        {
            return View(model);
        }

        if(await _userManager.Users.AnyAsync(u => u.Email == model.Email))
        {
            return View(model);
        }

        var user = new User()
        {
            Email = model.Email,
            PhoneNumber = model.Phone,
            UserName = model.Email[..model.Email.IndexOf('@')],
            Fullname = model.Fullname
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if(result.Succeeded)
        {
            await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
            return Redirect(model.ReturnUrl ?? "/");
        }

        return View(model);
    }

    // public async Task<IActionResult> Logout(string logoutId)
    // {
    //     return await HttpContext.SignOutAsync(logoutId);
    // }
    

    public IActionResult ExternalLogin(string provider, string returnUrl)
    {
        var callbackUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl = returnUrl ?? string.Empty });

        var props = new AuthenticationProperties
        {
            RedirectUri = callbackUrl,
            Items =
            {
                { "scheme", provider }
            }
        };

        return Challenge(props, provider);
    }

    public async Task<IActionResult> ExternalLoginCallback(string returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result?.Succeeded != true)
        {
            throw new Exception("External authentication error");
        }

        // retrieve claims of the external user
        var externalUser = result.Principal;
        if (externalUser == null)
        {
            throw new Exception("External authentication error");
        }

        var claims = externalUser.Claims.ToList();

        var userIdClaim = claims.Find(x => x.Type == JwtClaimTypes.Subject) ?? claims.Find(x => x.Type == ClaimTypes.NameIdentifier);
        var nameClaim = claims.Find(x => x.Type == JwtClaimTypes.Name) ?? claims.Find(x => x.Type == ClaimTypes.Name);
        var emailClaim = claims.Find(x => x.Type == JwtClaimTypes.Email) ?? claims.Find(x => x.Type == ClaimTypes.Email);

        if(emailClaim == null || userIdClaim == null)
        {
            return Redirect("Login");
        }

        var user = await _userManager.FindByEmailAsync(emailClaim.Value);
        if(user == null)
        {
            user = new User()
            {
                Fullname = nameClaim.Value,
                Email = emailClaim.Value,
                UserName = emailClaim.Value[..emailClaim.Value.IndexOf('@')],
                IsExternal = true,
                ExternalProvider = emailClaim.Issuer
            };

            var createResult = await _userManager.CreateAsync(user);
            if(!createResult.Succeeded)
            {
                return Redirect("Login");
            }
        }

        await _signInManager.SignInAsync(user, false);
        await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        return Redirect(returnUrl ?? "/");
    }
}