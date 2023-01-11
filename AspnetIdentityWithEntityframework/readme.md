## Identity 集成Entityframework

- 配置中间件

~~~ c#
builder.Services.AddDbContext<AppDbContext>(config =>
{
    config.UseInMemoryDatabase("Memory");
});

// AddIdentity registers the services
builder.Services.AddIdentity<IdentityUser, IdentityRole>(config =>
    {
        config.Password.RequiredLength = 4;
        config.Password.RequireDigit = false;
        config.Password.RequireNonAlphanumeric = false;
        config.Password.RequireUppercase = false;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(config =>
{
    config.Cookie.Name = "Identity.Cookie";
    config.LoginPath = "/Home/Login";
});
~~~



- 注意下面这个不需要配置了

~~~ c#
builder.Services.AddAuthentication("CookieAuth")
    .AddCookie("CookieAuth", config =>
    {
        config.Cookie.Name = "Grandmas.Cookie";
        config.LoginPath = "/Home/Authenticate";
    });
~~~



## 注册时 Email 确认

- 配置

 ~~~c#
 builder.Services.AddIdentity<IdentityUser, IdentityRole>(config =>
     {
         config.Password.RequiredLength = 4;
         config.Password.RequireDigit = false;
         config.Password.RequireNonAlphanumeric = false;
         config.Password.RequireUppercase = false;
         config.SignIn.RequireConfirmedEmail = true; //开启确认邮件
     })
     .AddEntityFrameworkStores<AppDbContext>()
     .AddDefaultTokenProviders();
 ~~~



- 注册action

~~~c#
[HttpPost]
public async Task<IActionResult> Register(string username, string password)
{
    //register functionality

    var user = new IdentityUser
    {
        UserName = username,
        Email = "",
    };

    var result = await _userManager.CreateAsync(user, password);

    if (result.Succeeded)
    {
        //sign in
        // var signInResult = await _signInManager.PasswordSignInAsync(user, password, false, false);
        //
        // if (signInResult.Succeeded)
        // {
        //     return RedirectToAction("Index");
        // }

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var link = Url.Action(nameof(VerifyEmail), "Home", new { userId = user.Id, code },Request.Scheme,Request.Host.ToString());

        await _emailService.SendAsync("test@test.com","email verify",$"<a href=\"{link}\">Verify email</a>",true);

        return RedirectToAction(nameof(EmailVerification));
    }

    return RedirectToAction("Index");
}
~~~



- 确认action

~~~ c#
 public async Task<IActionResult> VerifyEmail(string userId, string code)
 {
     var user = await _userManager.FindByIdAsync(userId);

     if (user==null)
     {
         return BadRequest();
     }

     var result = await _userManager.ConfirmEmailAsync(user, code);

     if (result.Succeeded)
     {
         return View();
     }

     return BadRequest();
 }
~~~



