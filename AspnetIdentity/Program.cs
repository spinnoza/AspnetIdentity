using System.Security.Claims;
using AspnetIdentity.AuthorizationRequirements;
using AspnetIdentity.CustomPolicyProvider;
using AspnetIdentity.Transformer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.


builder.Services.AddAuthentication("CookieAuth")
    .AddCookie("CookieAuth", config =>
    {
        config.Cookie.Name = "Grandmas.Cookie";
        config.LoginPath = "/Home/Authenticate";
    });

builder.Services.AddAuthorization(config =>
{
    //var defaultAuthBuilder = new AuthorizationPolicyBuilder();
    //var defaultAuthPolicy = defaultAuthBuilder
    //    .RequireAuthenticatedUser()
    //    .RequireClaim(ClaimTypes.DateOfBirth)
    //    .Build();

    //config.DefaultPolicy = defaultAuthPolicy;

    //config.AddPolicy("Claim.DoB", authPolicyBuilder =>
    //{
    //    authPolicyBuilder.RequireClaim(ClaimTypes.DateOfBirth);
    //});

    config.AddPolicy("Claim.DoB", authPolicyBuilder =>
    {
        //authPolicyBuilder.AddRequirements(new CustomRequireClaim(ClaimTypes.DateOfBirth));
        authPolicyBuilder.RequireCustomClaim(ClaimTypes.DateOfBirth);
    });


});


builder.Services.AddScoped<IAuthorizationHandler, CustomRequireClaimHandler>();

builder.Services.AddScoped<IClaimsTransformation, ClaimsTransformation>();

builder.Services.AddSingleton<IAuthorizationPolicyProvider, CustomAuthorizationPolicyProvider>();
builder.Services.AddScoped<IAuthorizationHandler, SecurityLevelHandler>();

// builder.Services.AddControllersWithViews(cofig =>
// {
//     //var defaultAuthBuilder = new AuthorizationPolicyBuilder();
//     //var defaultAuthPolicy = defaultAuthBuilder
//     //    .RequireAuthenticatedUser()
//     //    .Build();
//
//     //cofig.Filters.Add(new AuthorizeFilter(defaultAuthPolicy));
// });

builder.Services.AddControllersWithViews();


var app = builder.Build();



// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
