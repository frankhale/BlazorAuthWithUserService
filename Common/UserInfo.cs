namespace Common;

public sealed class UserInfo
{
    public required string Name { get; init; }
    public required string Email { get; init; }
    public required string Role { get; init; }
    public string? Jwt { get; init; }
}
