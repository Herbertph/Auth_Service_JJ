using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Domain.Entities;
using AuthService.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services;

public class JwtTokenService
{
    private readonly JwtOptions _opt;
    private readonly SigningCredentials _creds;
    private readonly string? _issuer;
    private readonly string? _audience;

    public JwtTokenService(JwtOptions options)
    {
        _opt = options ?? throw new ArgumentNullException(nameof(options));

        // Garante key >= 32 bytes (HS256)
        var keyText = _opt.Key ?? string.Empty;
        var keyBytes = Encoding.UTF8.GetBytes(keyText);
        if (keyBytes.Length < 32)
            throw new InvalidOperationException($"JWT key too short ({keyBytes.Length} bytes). Provide >= 32 bytes in Jwt:Key.");

        var key = new SymmetricSecurityKey(keyBytes);
        _creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        _issuer = string.IsNullOrWhiteSpace(_opt.Issuer) ? null : _opt.Issuer;
        _audience = string.IsNullOrWhiteSpace(_opt.Audience) ? null : _opt.Audience;
    }

    public string CreateAccessToken(User user)
    {
        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role, user.Role.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
        };

        var token = new JwtSecurityToken(
            issuer: _issuer,                 // só valida se configurado no Program.cs
            audience: _audience,             // só valida se configurado no Program.cs
            claims: claims,
            notBefore: now,                  // nbf
            expires: now.AddMinutes(_opt.AccessTokenMinutes),
            signingCredentials: _creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
