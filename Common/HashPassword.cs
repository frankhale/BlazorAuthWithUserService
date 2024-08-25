using System.Security.Cryptography;
using System.Text;

namespace Common;

public static class HashPassword
{
    public static string Create(string password)
    {
        var hashedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
    }
}