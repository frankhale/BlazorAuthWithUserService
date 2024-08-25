using AutoMapper;
using Common;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Text;
using UserService.AuthenticationAndAuthorization;
using UserService.Data;
using UserService.Data.Repository;
using UserService.Helpers;
using UserService.Middleware;
using SameSiteMode = Microsoft.AspNetCore.Http.SameSiteMode;

var jwtIssuer = Environment.GetEnvironmentVariable("JwtIssuer");
var jwtAudience = Environment.GetEnvironmentVariable("JwtAudience");
var jwtSecurityKey = Environment.GetEnvironmentVariable("JwtSecurityKey");
var dataProtectionSharedFolder = Environment.GetEnvironmentVariable("DataProtectionFolder");

if (string.IsNullOrEmpty(jwtIssuer) ||
    string.IsNullOrEmpty(jwtAudience) ||
    string.IsNullOrEmpty(jwtSecurityKey) ||
    string.IsNullOrEmpty(dataProtectionSharedFolder))
{
    Console.WriteLine(
        "Please check DataProtectionFolder, JwtIssuer, JwtAudience and JwtSecurityKey environment variables as one or more are missing.");
    Environment.Exit(1);
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "User Service API", Version = "v1" });
});

// REF: https://weblog.west-wind.com/posts/2022/Mar/29/Combining-Bearer-Token-and-Cookie-Auth-in-ASPNET
builder.Services.AddAuthentication(options =>
    {
        // custom scheme defined in .AddPolicyScheme() below
        options.DefaultScheme = "API_JWT_OR_COOKIE";
        options.DefaultChallengeScheme = "API_JWT_OR_COOKIE";
    })
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationOptions.DefaultScheme, options => { })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };

        options.Cookie.Name = "BlazorCookieAuth";
        options.Cookie.SameSite = SameSiteMode.None; // Required for cross-site
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Secure is mandatory for SameSite=None
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecurityKey)),
        };
    })
    .AddPolicyScheme("API_JWT_OR_COOKIE", "API_JWT_OR_COOKIE", options =>
    {
        // runs on each request
        options.ForwardDefaultSelector = context =>
        {
            // filter by auth type
            string? authorization = context.Request.Headers[HeaderNames.Authorization];
            
            if (!string.IsNullOrEmpty(authorization))
            {
                if (authorization.StartsWith("Bearer "))
                {
                    return JwtBearerDefaults.AuthenticationScheme;
                }
                else if (authorization.StartsWith("X-Api-Key"))
                {
                    return ApiKeyAuthenticationOptions.DefaultScheme;
                }
            }

            // otherwise always check for cookie auth
            return CookieAuthenticationDefaults.AuthenticationScheme;
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthorizationHandler, DebugRoleAuthorizationHandler>();

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("APIUser", policy =>
    {
        policy.AuthenticationSchemes.Add("API_JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("APIUser");
    })
    .AddPolicy("BasicUser", policy =>
    {
        policy.AuthenticationSchemes.Add("API_JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("BasicUser");
    })
    .AddPolicy("User", policy =>
    {
        policy.AuthenticationSchemes.Add("API_JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("User");
    })
    .AddPolicy("Admin", policy =>
    {
        policy.AuthenticationSchemes.Add("API_JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Admin");
    });

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionSharedFolder))
    .SetApplicationName("BlazorCookieAuth");

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalHost",
        policyBuilder =>
        {
            policyBuilder.WithOrigins("https://localhost")
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        });
});

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseSqlite("Filename=users.db"));

builder.Services.AddAutoMapper(Assembly.GetExecutingAssembly());

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddFilter("Microsoft.AspNetCore.AuthenticationAndAuthorization", LogLevel.Trace);
builder.Logging.AddFilter("Microsoft.AspNetCore.DataProtection", LogLevel.Trace);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "User Service API");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseMiddleware<RequestLoggingMiddleware>();
app.UseCors("AllowLocalHost");
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login",
    [Authorize(Policy = "BasicUser")] async (HttpContext context,
        ILogger<Program> logger,
        IUserRepository userRepository,
        IMapper mapper,
        [FromBody] LoginModel loginModel) =>
    {
        if (context.User.Identity is not { IsAuthenticated: true })
            return Results.Unauthorized();
        
        var user = await userRepository.GetUserByEmailAndPasswordAsync(loginModel.Username, loginModel.Password);
        
        if (user == null)
        {
            return Results.Unauthorized();
        }

        try
        {
            var userInfo = mapper.Map<UserInfo>(user);

            var token = JwtHelper.GetJwtToken(
                user.Name,
                jwtSecurityKey,
                jwtIssuer,
                jwtAudience,
                TimeSpan.FromDays(30),
                userInfo.Claims().ToArray()
            );

            userInfo.Jwt = new JwtSecurityTokenHandler().WriteToken(token);
            logger.LogInformation("JWT: {jwt}", userInfo.Jwt);
            return Results.Json(userInfo);
        }
        catch (AutoMapperMappingException ex)
        {
            return Results.Problem();
        }
    });

app.MapGet("/user/{id}", [Authorize(Policy = "APIUser")]
    async (IUserRepository userRepository, string id) =>
{
    var user = await userRepository.GetUserByIdAsync(id);
    return user != null ? Results.Json(user) : Results.NotFound();
});

app.MapGet("/secure-user",
    [Authorize(Policy = "User")](HttpContext context) =>
        Results.Ok(context.User.Identity is { IsAuthenticated: true }
            ? $"(USER Policy) Hello, {context.User.Identity.Name}"
            : Results.Unauthorized()));

app.MapGet("/secure-admin",
    [Authorize(Policy = "Admin")](HttpContext context) =>
        Results.Ok(context.User.Identity is { IsAuthenticated: true }
            ? $"(ADMIN Policy) Hello, {context.User.Identity.Name}"
            : Results.Unauthorized()));

app.Run();