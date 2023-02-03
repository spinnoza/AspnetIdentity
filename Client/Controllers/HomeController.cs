using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Client.Controllers
{
    public class HomeController: Controller
    {
        private readonly HttpClient _client;
        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _client = httpClientFactory.CreateClient();
        }
     
        public IActionResult Index()
        {
            return View();
        }

        //[Authorize]
        //public async Task<IActionResult> Secret()
        //{
        //    var token = await HttpContext.GetTokenAsync("access_token");

        //    return View();
        //}

        [Authorize]
        public async Task<IActionResult> Secret()
        {
            var token = await HttpContext.GetTokenAsync("access_token");

            _client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            //var serverResponse = await _client.GetAsync("https://localhost:7265/secret/index");
            //var serverMessage = await serverResponse.Content.ReadAsStringAsync();
           
            
            var apiResponse = await _client.GetAsync("https://localhost:7103/secret/index");
            var apiMessage = await apiResponse.Content.ReadAsStringAsync();

            return View();
        }
    }
}


