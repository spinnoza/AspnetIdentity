var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(config => {
        config.DefaultScheme = "Cookie";
        config.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("Cookie")
    .AddOpenIdConnect("oidc", config => {
        config.Authority = "https://localhost:7227/";
        config.ClientId = "client_id_mvc";
        config.ClientSecret = "client_secret_mvc";
        config.SaveTokens = true;

        config.ResponseType = "code";

        
    });

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
