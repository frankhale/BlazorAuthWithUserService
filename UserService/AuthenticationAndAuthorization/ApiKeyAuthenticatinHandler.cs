using Microsoft.Net.Http.Headers;
using UserService.Data.Repository;

namespace UserService.AuthenticationAndAuthorization;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "APIKEY";
    public static string Scheme => DefaultScheme;
    public const string AuthenticationType = DefaultScheme;
}

public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory logger,
    IUserRepository userRepository,
    UrlEncoder encoder)
    : AuthenticationHandler<ApiKeyAuthenticationOptions>(options, logger, encoder)
{
    private const string ApiKeyHeaderName = "X-Api-Key";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? apiKeyHeader = Request.Headers[HeaderNames.Authorization];
        
        if (apiKeyHeader == null || !apiKeyHeader.StartsWith("X-Api-Key"))
        {
            return AuthenticateResult.NoResult();
        }

        var providedApiKey = apiKeyHeader.Replace(ApiKeyHeaderName, string.Empty).Trim();
        bool isValidApiKey = false;
        if (Guid.TryParse(providedApiKey, out var parsedApiKey))
        {
            isValidApiKey = await userRepository.ValidateApiKeyAsync(parsedApiKey);
        }
        
        if (isValidApiKey)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "API"),
                new Claim(ClaimTypes.Role, "APIUser"),
            };
            var identity = new ClaimsIdentity(claims, ApiKeyAuthenticationOptions.AuthenticationType);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationOptions.Scheme);

            return AuthenticateResult.Success(ticket);
        }
        else
        {
            return AuthenticateResult.Fail("Invalid API Key provided.");
        }
    }
}
