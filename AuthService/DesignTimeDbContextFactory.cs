using System.IO;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using AuthService.Data;

namespace AuthService;

// Usada APENAS pelo "dotnet ef" para criar o DbContext sem subir o Program.cs
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var basePath = Directory.GetCurrentDirectory();

        var config = new ConfigurationBuilder()
            .SetBasePath(basePath)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        // Usa a mesma key do Program.cs, com fallback para o Postgres do docker (porta 5440 no host)
        var conn =
            config.GetConnectionString("Default")
            ?? config["ConnectionStrings:Default"]
            ?? "Host=localhost;Port=5440;Database=authdb;Username=authuser;Password=authpass";

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(conn)
            .Options;

        return new AuthDbContext(options);
    }
}
