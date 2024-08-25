using UserService.Data.Entities;

namespace UserService.Data.Repository;

public interface IUserRepository
{
    User? GetUserByEmailAndPassword(string email, string password);
}