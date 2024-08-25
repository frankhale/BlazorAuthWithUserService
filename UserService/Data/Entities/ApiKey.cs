using System.ComponentModel.DataAnnotations;

namespace UserService.Data.Entities;

public class ApiKey
{
    [Key] public required Guid Id { get; init; }
    [Required] [MaxLength(32)] public required Guid Value { get; init; }
}