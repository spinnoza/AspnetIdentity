using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiOne.Controllers
{
    public class SecretController : Controller
    {
      
       [Authorize]
        public string Index()
        {
            return "secret message from ApiOne";
        }
    }
}
