using System.ComponentModel.DataAnnotations;

namespace UserService.Data.Entities;

public class User
{
    [Key]
    public Guid Id { get; init; }
    [Required]
    [MaxLength(50)]
    public required string Name { get; init; }
    [Required]
    [EmailAddress]
    [MaxLength(50)]
    public required string Email { get; init; }
    [Required]
    [MaxLength(50)]
    public required string Password { get; init; }
}