using Common;
using UserService.Data.Entities;

namespace UserService.Data.Repository;

public class UserRepository(UserDbContext context) : IUserRepository
{
    public User? GetUserByEmailAndPassword(string email, string password)
    {
        // Look up the user by email and hashed password
        return context.Users.FirstOrDefault(user => 
            user.Email == email && 
            user.Password == HashPassword.Create(password));
    }
}
