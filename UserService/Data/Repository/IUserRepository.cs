using UserService.Data.Entities;

namespace UserService.Data.Repository;

public interface IUserRepository
{
    Task<bool> ValidateApiKeyAsync(Guid apiKey);
    Task<User?> GetUserByIdAsync(string id);
    Task<User?> GetUserByEmailAndPasswordAsync(string email, string password);
}