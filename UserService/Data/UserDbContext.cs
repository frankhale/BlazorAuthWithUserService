using Common;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using UserService.Data.Entities;

namespace UserService.Data;

public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
{
    public DbSet<User> Users { get; init; }
    public DbSet<ApiKey> ApiKeys { get; init; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ApiKey>().HasData(
            new ApiKey
            {
                Id = Guid.NewGuid(),
                Value = Guid.Parse("10000000-1000-1000-1000-100000000000")
            }
        );
        
        modelBuilder.Entity<User>().HasData(
            new User
            {
                Id = Guid.NewGuid(),
                Name = "Fred Smith",
                Email = "fred.smith@example.com",
                Password = HashPassword.Create("1234"),
                Role= "User"
            }
        );
    }
}