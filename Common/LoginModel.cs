using System.ComponentModel.DataAnnotations;

namespace Common;

public sealed class LoginModel
{
    [Required]
    [EmailAddress]
    public string Username { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}