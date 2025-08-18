using AuthService.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Data;

public class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var user = modelBuilder.Entity<User>();
        user.ToTable("users");
        user.Property(u => u.Name).HasMaxLength(120).IsRequired();
        user.Property(u => u.Email).HasMaxLength(180).IsRequired();
        user.Property(u => u.Username).HasMaxLength(50).IsRequired();
        user.Property(u => u.PasswordHash).IsRequired();

        // Role enum como string legível
        user.Property(u => u.Role)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        user.HasIndex(u => u.Email).IsUnique();
        user.HasIndex(u => u.Username).IsUnique();

        var rt = modelBuilder.Entity<RefreshToken>();
        rt.ToTable("refresh_tokens");
        rt.Property(r => r.TokenHash).IsRequired();
        rt.HasIndex(r => new { r.UserId, r.TokenHash }).IsUnique();
        rt.HasOne(r => r.User)
          .WithMany(u => u.RefreshTokens)
          .HasForeignKey(r => r.UserId)
          .OnDelete(DeleteBehavior.Cascade);

        base.OnModelCreating(modelBuilder);
    }
}
