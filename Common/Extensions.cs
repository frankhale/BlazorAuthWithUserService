using System.Security.Claims;

namespace Common;

public static class Extensions
{
    public static UserInfo? ToUserInfo(this ClaimsPrincipal principal)
    {
        var id = principal.FindFirst("id")?.Value;
        var name = principal.FindFirst(ClaimTypes.Name)?.Value;
        var email = principal.FindFirst(ClaimTypes.Email)?.Value;
        var role = principal.FindFirst(ClaimTypes.Role)?.Value;
        var jwt = principal.FindFirst("jwt")?.Value;

        if (!string.IsNullOrEmpty(id) && 
            !string.IsNullOrEmpty(name) && 
            !string.IsNullOrEmpty(email) && 
            !string.IsNullOrEmpty(role) && 
            !string.IsNullOrEmpty(jwt))
        {
            return new UserInfo
            {
                Id = Guid.Parse(id),
                Name = name,
                Email = email,
                Role = role,
                Jwt = jwt
            };
        }

        return null;
    }
    public static List<Claim> Claims(this UserInfo userInfo)
    {
        List<Claim> claims =
        [
            new Claim("id", userInfo.Id.ToString()),
            new Claim(ClaimTypes.Name, userInfo.Name),
            new Claim(ClaimTypes.Email, userInfo.Email),
            new Claim(ClaimTypes.Role, userInfo.Role)
        ];

        if (!string.IsNullOrEmpty(userInfo.Jwt))
        {
            claims.Add(new Claim("jwt", userInfo.Jwt));
        }

        return claims;
    }
}