using AuthService.Domain.Enums;

namespace AuthService.Domain.Entities;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = default!;
    public string Email { get; set; } = default!;        // único
    public string Username { get; set; } = default!;     // único
    public string PasswordHash { get; set; } = default!;

    public UserRole Role { get; set; } = UserRole.Bettor;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    public List<RefreshToken> RefreshTokens { get; set; } = new();
}
