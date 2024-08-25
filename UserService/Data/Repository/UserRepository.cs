using Common;
using Microsoft.EntityFrameworkCore;
using UserService.Data.Entities;

namespace UserService.Data.Repository;

public class UserRepository(UserDbContext context) : IUserRepository
{
    public async Task<bool> ValidateApiKeyAsync(Guid apiKey)
    {
        return await context.ApiKeys.AnyAsync(x => x.Value == apiKey);
    }
    
    public Task<User?> GetUserByIdAsync(string id)
    {
        return context.Users.FirstOrDefaultAsync(user => user.Id == Guid.Parse(id)); 
    }
    public Task<User?> GetUserByEmailAndPasswordAsync(string email, string password)
    {
        return context.Users.FirstOrDefaultAsync(user => 
            user.Email == email && 
            user.Password == HashPassword.Create(password));
    }
}
