using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorAuthWithUserService.Pages;

public class FinishLogin2(
    IHttpContextAccessor httpContextAccessor,
    IHttpClientFactory httpClientFactory,
    ILogger<FinishLogin2> logger,
    LoginHelper loginHelper) : PageModel
{
    public async Task<IActionResult> OnGet()
    {
        httpContextAccessor.HttpContext!.Request.Cookies.TryGetValue("BlazorCookieAuth", out var authCookie);

        if (string.IsNullOrEmpty(authCookie)) return Page();
        logger.LogInformation($"BlazorAuthCookie: {authCookie}");

        var loginInfo = loginHelper.GetLogin(authCookie);

        if (loginInfo is { LoginModel: null })
        {
            httpContextAccessor.HttpContext.Response.Redirect("/Forbidden");
        }
        
        var userServiceClient = httpClientFactory.CreateClient("MyHttpClient");
        var cookieHeader = new CookieHeaderValue("BlazorCookieAuth", authCookie);
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7000/login");
        request.Content = JsonContent.Create(loginInfo!.LoginModel);
        request.Headers.Add("Cookie", cookieHeader.ToString());
        var response = await userServiceClient.SendAsync(request);

        loginHelper.RemoveLogin(authCookie);

        if (!response.IsSuccessStatusCode)
        {
            httpContextAccessor.HttpContext.Response.Redirect("/Forbidden");
        }
        
        var responseData = await response.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<UserInfo>(responseData, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (userInfo == null)
        {
            httpContextAccessor.HttpContext.Response.Redirect("/Forbidden");
        }

        logger.LogInformation($"Name: {userInfo?.Name}");
        logger.LogInformation($"Email: {userInfo?.Email}");
        logger.LogInformation($"Role: {userInfo?.Role}");

        await httpContextAccessor.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (userInfo == null) return Page();
        
        var claimsIdentity = new ClaimsIdentity(
            userInfo.Claims(), CookieAuthenticationDefaults.AuthenticationScheme);

        await httpContextAccessor.HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties
            {
                AllowRefresh = true,
                IsPersistent = true
            });
            
        httpContextAccessor.HttpContext.Response.Redirect("/");

        return Page();
    }
}