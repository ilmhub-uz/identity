using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace identity.Controllers;

public class HomeController : Controller
{
    [Authorize]
    public IActionResult Index() => View();
}