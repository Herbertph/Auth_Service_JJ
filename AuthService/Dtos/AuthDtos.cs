namespace AuthService.Dtos;

public record RegisterRequest(string Name, string Email, string Username, string Password);
public record LoginRequest(string UsernameOrEmail, string Password);
public record CreateOrganizerRequest(string Name, string Email, string Username, string Password);
public record AuthResponse(string accessToken, string refreshToken);
