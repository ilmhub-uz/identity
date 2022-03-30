using System.Security.Claims;
using identity.Entity;
using identity.Services;
using identity.ViewModels;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ilmhub.core;
using ilmhub.model;
using identity.Data;
using identity.Mappers;

namespace identity.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly IIdentityServerInteractionService _interactionService;
    private readonly MessageQueue<KeyValuePair<Guid, Message>> _queue;
    private readonly ApplicationDbContext _context;

    public AccountController(
        SignInManager<User> signInManager,
        UserManager<User> userManager,
        IIdentityServerInteractionService interactionService,
        MessageQueue<KeyValuePair<Guid, Message>> queue,
        ApplicationDbContext context)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _interactionService = interactionService;
        _queue = queue;
        _context = context;
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
            model.ExternalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync();
            ModelState.AddModelError("Email", "Email or password is wrong.");
            return View(model);
        }

        return Redirect(model.ReturnUrl ?? "/");
    }

    public async Task<IActionResult> Register(string returnUrl)
    {
        return View(new RegisterViewModel() 
        { 
            ReturnUrl = returnUrl,
            ExternalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync()
        });
    }

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
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            // TODO: this URlActoin is wrong.
            // https:localhost:1223/account/confirmemail?token={}&id={}
            var confirmUrl = Url.Action("ConfirmEmail", "Account", new { token, user.Id});

            var htmlContent = $"Welcome to Ilmhub, please <a href='{confirmUrl}'>confirm your email</a>";

            var emailMessage = new ilmhub.entity.Message("EmailConfirmation", EMessageType.Email, "no-reply@ilmhub.uz", "Ilmhub", "wakhid2802@gmail.com", user.Fullname, "Confirm your account at Ilmhub", "", htmlContent);

            _context.Messages.Add(emailMessage);
            await _context.SaveChangesAsync();
            
            _queue.Queue(KeyValuePair.Create(emailMessage.Id, emailMessage.ToModel()));

            return RedirectToAction(nameof(EmailConfirmationSent));
        }

        return View(model);
    }

    public IActionResult EmailConfirmationSent() => View();
    

    public async Task<IActionResult> Logout(string logoutId)
    {
        await _signInManager.SignOutAsync();

        var logoutRequest = await _interactionService.GetLogoutContextAsync(logoutId);
        if(string.IsNullOrWhiteSpace(logoutRequest?.PostLogoutRedirectUri))
        {
            return RedirectToAction("Index", "Home");
        }

        return Redirect(logoutRequest.PostLogoutRedirectUri);
    }
    public IActionResult ExternalLogin(string provider, string returnUrl, string method) // method: Login | Register
    {
        if(string.IsNullOrWhiteSpace(method))
        {
            return RedirectToAction(nameof(Login));
        }

        var callbackAction = method.ToLowerInvariant() switch
        {
            "login" => nameof(ExternalLoginCallback),
            "register" => nameof(ExternalRegisterCallback),
            _ => nameof(ExternalLoginCallback)
        };

        var callbackUrl = Url.Action(
            action: callbackAction,
            controller: "Account",
            values: new { returnUrl = returnUrl ?? string.Empty });

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

    public async Task<IActionResult> ExternalRegisterCallback(string returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result?.Succeeded != true)
        {
            ViewData["ErrorMessage"] = "External login failed";
            // TODO: log detailed error
            return Redirect("/error");
        }

        var externalUser = result.Principal;
        if (externalUser == null)
        {
            ViewData["ErrorMessage"] = "External login failed";
            // TODO: log detailed error
            return Redirect("/error");
        }

        var claims = externalUser.Claims.ToList();
        var email = claims.Find(x => x.Type == JwtClaimTypes.Email) ?? claims.Find(x => x.Type == ClaimTypes.Email);
        if (string.IsNullOrWhiteSpace(email?.Value))
        {
            ViewData["ErrorMessage"] = "External login failed";
            // TODO: log detailed error
            return Redirect("/error");
        }

        if(await _userManager.Users.AnyAsync(u => u.Email == email.Value))
        {
            return View(nameof(Register), new RegisterViewModel()
            {
                ErrorMessage = "User with this email already exists.",
                ExternalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync(),
                ReturnUrl = returnUrl
            });
        }

        var nameClaim = claims.Find(x => x.Type == JwtClaimTypes.Name) ?? claims.Find(x => x.Type == ClaimTypes.Name);

        return View(nameof(Register), new RegisterViewModel()
        {
            ExternalProviders = await _signInManager.GetExternalAuthenticationSchemesAsync(),
            ReturnUrl = returnUrl,
            Email = email.Value,
            Fullname = nameClaim.Value,
            IsExternal = true
        });
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