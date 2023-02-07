using Microsoft.AspNetCore.Mvc;

namespace ApiOne.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
