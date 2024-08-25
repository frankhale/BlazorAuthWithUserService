using BlazorCookieAuth;
using BlazorCookieAuth.Components;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Net;

var dataProtectionSharedFolder = Environment.GetEnvironmentVariable("DataProtectionFolder");

if (string.IsNullOrEmpty(dataProtectionSharedFolder))
{
    Console.WriteLine("Please check DataProtectionFolder environment variable.");
    Environment.Exit(1);
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider, PersistingRevalidatingAuthenticationStateProvider>();
builder.Services.AddSingleton<LoginHelper>();

builder.Services.AddHttpClient("MyHttpClient")
    .AddHttpMessageHandler(() => new HttpClientLoggingHandler())
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        CookieContainer = new CookieContainer(),
        UseCookies = true
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.AccessDeniedPath = "/forbidden";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromDays(30);
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.Name = "BlazorCookieAuth";
        
        options.Events.OnRedirectToLogin = opt =>
        {
            opt.HttpContext.Response.Redirect("/login");
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("BasicUser", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("BasicUser");
    })
    .AddPolicy("User", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("User");
    })
    .AddPolicy("Admin", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Admin");
    });

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionSharedFolder))
    .SetApplicationName("BlazorCookieAuth");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(BlazorCookieAuth.Client._Imports).Assembly);

app.Run();
