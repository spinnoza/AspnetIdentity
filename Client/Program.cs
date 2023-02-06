using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews().AddRazorRuntimeCompilation();

builder.Services.AddAuthentication(config => {
        // We check the cookie to confirm that we are authenticated
        config.DefaultAuthenticateScheme = "ClientCookie";
        // When we sign in we will deal out a cookie
        config.DefaultSignInScheme = "ClientCookie";
        // use this to check if we are allowed to do something.
        config.DefaultChallengeScheme = "OurServer";
    })
    .AddCookie("ClientCookie")
    .AddOAuth("OurServer", config => {
        config.ClientId = "client_id";
        config.ClientSecret = "client_secret";
         config.CallbackPath = new PathString("/authorization-code/callback");
        config.AuthorizationEndpoint = "https://localhost:7265/oauth/authorize";
        config.TokenEndpoint = "https://localhost:7265/oauth/token";
        

        config.SaveTokens = true;
        

        config.Events = new OAuthEvents()
        {
            OnCreatingTicket = context =>
            {
                var accessToken = context.AccessToken;
                if (accessToken!=null)
                {
                    var base64payload = accessToken.Split('.')[1];
                    var bytes = Convert.FromBase64String(base64payload);
                    var jsonPayload = Encoding.UTF8.GetString(bytes);
                    var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonPayload);

                    foreach (var claim in claims)
                    {
                        context.Identity?.AddClaim(new Claim(claim.Key, claim.Value));
                    }

                   
                }

                return Task.CompletedTask;

            }
        };
    });
builder.Services.AddHttpClient();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
