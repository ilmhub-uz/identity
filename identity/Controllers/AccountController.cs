using identity.Entity;
using identity.ViewModels;
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

    public IActionResult Login(string returnUrl)
        => View(new LoginViewModel() { ReturnUrl = returnUrl });
    
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
}