using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace BlazorAuthWithUserService.Pages;

public class Login2(
    IHttpContextAccessor httpContextAccessor,
    LoginHelper loginHelper)
    : PageModel
{
    [BindProperty]
    public string? Username { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    public bool UsernameError { get; set; }
    public bool PasswordError { get; set; }
    
    public async Task<IActionResult> OnGet()
    {
        if (httpContextAccessor.HttpContext != null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await httpContextAccessor.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        // Validate the form input
        UsernameError = string.IsNullOrWhiteSpace(Username);
        PasswordError = string.IsNullOrWhiteSpace(Password);
        
        if (UsernameError || PasswordError)
        {
            return Page(); 
        }
        
        var loginInput = new LoginModel
        {
            Username = Username!,
            Password = Password!
        };
        
        var claims = new List<Claim>
        {
            new(ClaimTypes.Email, loginInput.Username),
            new(ClaimTypes.Role, "BasicUser"),
        };

        var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);

        if (httpContextAccessor.HttpContext != null)
        {
            await httpContextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = true
                });
           
            httpContextAccessor.HttpContext!.Response.Headers.TryGetValue("Set-Cookie", out var setCookie);
            var authCookie = setCookie[0]!.Split(";")[0].Replace("BlazorCookieAuth=", "");
            loginHelper.SetLogin(authCookie, loginInput);
            
            return RedirectToPage("/Spinner2");
        }
        else
        {
            httpContextAccessor.HttpContext!.Response.Redirect("/Forbidden");
        }

        return Page();
    }
}