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

