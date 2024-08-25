using Common;

namespace BlazorCookieAuth;

public class LoginHelper
{
    public Dictionary<string, LoginModel?> LoginLookup { get; } = new();
}