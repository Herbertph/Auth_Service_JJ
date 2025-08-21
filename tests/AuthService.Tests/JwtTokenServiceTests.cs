using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Options;
using AuthService.Services;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.Tests;

public class JwtTokenServiceTests
{
    [Fact]
    public void CreateAccessToken_GeraTokenComClaimsEAssinaturaValidas()
    {
        // arrange
        var key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var opts = new JwtOptions
        {
            Issuer = "issuer-test",
            Audience = "aud-test",
            Key = key,
            AccessTokenMinutes = 10
        };
        var service = new JwtTokenService(opts);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = "tester",
            Role = UserRole.Bettor
        };

        // act
        var token = service.CreateAccessToken(user);

        // assert assinatura e claims
        var handler = new JwtSecurityTokenHandler();

        // Mantenha o mapeamento padrão (sub -> nameidentifier).
        // Se quiser forçar sem mapear, descomente a linha abaixo e ajuste as asserts para "sub".
        // JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            ValidateIssuer = true,
            ValidIssuer = opts.Issuer,
            ValidateAudience = true,
            ValidAudience = opts.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(5)
        };

        var principal = handler.ValidateToken(token, parameters, out var secToken);

        // sub pode chegar como NameIdentifier devido ao mapeamento padrão
        var sub = principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
                  ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
        sub.Should().Be(user.Id.ToString());

        // username pode chegar como "username", "unique_name" ou Name
        var uname = principal.FindFirstValue("username")
                    ?? principal.FindFirstValue(JwtRegisteredClaimNames.UniqueName)
                    ?? principal.FindFirstValue(ClaimTypes.Name);
        uname.Should().Be(user.Username);

        // role mapeada
        principal.IsInRole(user.Role.ToString()).Should().BeTrue();

        secToken.Should().BeOfType<JwtSecurityToken>();
    }
}
