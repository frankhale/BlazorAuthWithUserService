using System.IdentityModel.Tokens.Jwt;
using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using UserService;
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
    Console.WriteLine("Please check DataProtectionFolder, JwtIssuer, JwtAudience and JwtSecurityKey environment variables as one or more are missing.");
    Environment.Exit(1);
}

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "User Service API", Version = "v1" });

    c.AddSecurityDefinition("CookieAuth", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Cookie,
        Name = "BlazorCookieAuth",
        Scheme = "CookieAuth"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "CookieAuth"
                }
            },
            new List<string>()
        }
    });
});

// builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//     .AddCookie(options =>
//     {
//         options.Events.OnRedirectToLogin = context =>
//         {
//             context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//             return Task.CompletedTask;
//         };
//         options.Events.OnRedirectToAccessDenied = context =>
//         {
//             context.Response.StatusCode = StatusCodes.Status403Forbidden;
//             return Task.CompletedTask;
//         };
//
//         options.Cookie.Name = "BlazorCookieAuth";
//         options.Cookie.SameSite = SameSiteMode.None; // Required for cross-site
//         options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Secure is mandatory for SameSite=None
//     });

// REF: https://weblog.west-wind.com/posts/2022/Mar/29/Combining-Bearer-Token-and-Cookie-Auth-in-ASPNET
builder.Services.AddAuthentication(options =>
    {
        // custom scheme defined in .AddPolicyScheme() below
        options.DefaultScheme = "JWT_OR_COOKIE";
        options.DefaultChallengeScheme = "JWT_OR_COOKIE";
    })
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
    .AddPolicyScheme("JWT_OR_COOKIE", "JWT_OR_COOKIE", options =>
    {
        // runs on each request
        options.ForwardDefaultSelector = context =>
        {
            // filter by auth type
            string? authorization = context.Request.Headers[HeaderNames.Authorization];
            if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                return JwtBearerDefaults.AuthenticationScheme;

            // otherwise always check for cookie auth
            return CookieAuthenticationDefaults.AuthenticationScheme;
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<IAuthorizationHandler, DebugRoleAuthorizationHandler>();

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("BasicUser", policy =>
    {
        policy.AuthenticationSchemes.Add("JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("BasicUser");
    })
    .AddPolicy("User", policy =>
    {
        policy.AuthenticationSchemes.Add("JWT_OR_COOKIE");
        policy.RequireAuthenticatedUser();
        policy.RequireRole("User");
    })
    .AddPolicy("Admin", policy =>
    {
        policy.AuthenticationSchemes.Add("JWT_OR_COOKIE");
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

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Trace);
builder.Logging.AddFilter("Microsoft.AspNetCore.DataProtection", LogLevel.Trace);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "User Service API");
        c.RoutePrefix = string.Empty; // Serve Swagger UI at the app's root
    });
}

app.UseHttpsRedirection();

app.UseMiddleware<RequestLoggingMiddleware>();

app.UseCors("AllowLocalHost");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login",
    [Authorize(Policy = "BasicUser")](HttpContext context) =>
    {
        if (context.User.Identity is not { IsAuthenticated: true })
            return Results.Unauthorized();

        var userName = context.User.FindFirstValue(ClaimTypes.Name);
        var email = context.User.FindFirstValue(ClaimTypes.Email);

        if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(email))
        {
            return Results.Unauthorized();
        }

        // create a new token with token helper and add our claim
        var token = JwtHelper.GetJwtToken(
            userName,
            jwtSecurityKey,
            jwtIssuer,
            jwtAudience,
            TimeSpan.FromMinutes(60),
            new[]
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Email, email),
                new Claim(ClaimTypes.Role, "User"),
            });
        
        return Results.Json(new UserInfo
        {
            Name = userName,
            Email = email,
            Role = "User",
            Jwt = new JwtSecurityTokenHandler().WriteToken(token)
        });
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