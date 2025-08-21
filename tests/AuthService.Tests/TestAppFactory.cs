using System.Security.Claims;
using AuthService;
using AuthService.Data;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests;

public class TestAppFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // ambiente de testes
        builder.UseEnvironment("Testing");

        // overrides de config (usando as mesmas chaves que o Program.cs lê)
        var overrides = new Dictionary<string, string?>
        {
            // Program.cs lê isto:
            ["Testing:UseInMemory"] = "true",

            // Program.cs/ JwtOptions
            ["Jwt:Key"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ["Jwt:Issuer"] = "jj-arena-auth",
            ["Jwt:Audience"] = "jj-arena",
            ["Jwt:AccessTokenMinutes"] = "15",
            ["Jwt:RefreshTokenDays"] = "7",

            // opcional: seed usado no Program.cs
            ["Seed:AdminEmail"] = "admin@test.local",
            ["Seed:AdminPassword"] = "Admin#123"
        };

        // 1) Injeta nas configurações
        builder.ConfigureAppConfiguration((_, cfg) =>
        {
            cfg.AddInMemoryCollection(overrides);
        });

        // 2) Injeta também via UseSetting (garante visibilidade bem cedo)
        foreach (var kv in overrides)
            builder.UseSetting(kv.Key, kv.Value);

        // 3) Força DbContext InMemory e faz seed do user de teste
        builder.ConfigureServices(services =>
        {
            // remove Npgsql se registrado
            var dbCtx = services.FirstOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
            if (dbCtx is not null) services.Remove(dbCtx);

            services.AddDbContext<AuthDbContext>(opt =>
                opt.UseInMemoryDatabase("AuthTestsDb"));

            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

            db.Database.EnsureDeleted();
            db.Database.EnsureCreated();

            if (!db.Users.Any(u => u.Email == "user@test.local"))
            {
                db.Users.Add(new Domain.Entities.User
                {
                    Id = Guid.NewGuid(),
                    Name = "User Test",
                    Email = "user@test.local",
                    Username = "user",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("P@ssw0rd!"),
                    Role = UserRole.Bettor
                });
                db.SaveChanges();
            }
        });
    }
}
