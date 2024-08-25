using Common;

namespace BlazorCookieAuth;

public sealed record LoginInfo(LoginModel? LoginModel, DateTime CreatedAt);

public sealed class LoginHelper : IDisposable
{
    private readonly Dictionary<string, LoginInfo> _loginLookup;
    private readonly Timer _cleanupTimer;
    
    public LoginHelper()
    {
        _loginLookup = new Dictionary<string, LoginInfo>();
        _cleanupTimer = new Timer(CleanupOldLogins, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
    }
    
    public void SetLogin(string key, LoginModel loginModel) => _loginLookup[key] = new LoginInfo(loginModel, DateTime.Now);

    public void RemoveLogin(string key)
    {
        _loginLookup.Remove(key);
    } 
    
    public LoginInfo? GetLogin(string key)
    {
        _loginLookup.TryGetValue(key, out var loginInfo);
        return loginInfo;
    }

    private void CleanupOldLogins(object? state)
    {
        var keysToRemove = _loginLookup
            .Where(kvp => (DateTime.Now - kvp.Value.CreatedAt).TotalSeconds >= 15)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            _loginLookup.Remove(key);
        }
    }
    
    public void Dispose()
    {
        _cleanupTimer.Dispose();
    }
}