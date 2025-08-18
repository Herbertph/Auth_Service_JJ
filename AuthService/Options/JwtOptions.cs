namespace AuthService.Options;

public class JwtOptions
{
    public string Issuer { get; set; } = "jj-arena-auth";
    public string Audience { get; set; } = "jj-arena";
    public string Key { get; set; } = default!;
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 14;
}
