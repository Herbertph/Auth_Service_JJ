using System.Security.Claims;
using System.Text;
using AuthService.Data;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Dtos;
using AuthService.Options;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// DbContext
var conn = builder.Configuration.GetConnectionString("Default")
           ?? builder.Configuration["ConnectionStrings:Default"];
builder.Services.AddDbContext<AuthDbContext>(opt => opt.UseNpgsql(conn));

// Options
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
var jwtOpts = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()!;
builder.Services.AddSingleton(jwtOpts);
builder.Services.Configure<SeedOptions>(builder.Configuration.GetSection("Seed"));

// AuthN
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(opt =>
  {
      opt.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOpts.Key)),
          ValidateIssuer = false,
          ValidateAudience = false,
          ValidateLifetime = true
      };
  });

// AuthZ (policies)
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("AdminOnly", p => p.RequireRole(UserRole.Admin.ToString()));
    opts.AddPolicy("OrganizerOrAdmin", p => p.RequireRole(UserRole.Organizer.ToString(), UserRole.Admin.ToString()));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<JwtTokenService>();

var app = builder.Build();

// Auto-migrate + seed admin
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.MigrateAsync();

    var seed = app.Configuration.GetSection("Seed").Get<SeedOptions>();
    if (!string.IsNullOrWhiteSpace(seed?.AdminEmail) && !await db.Users.AnyAsync(u => u.Email == seed.AdminEmail))
    {
        db.Users.Add(new User
        {
            Name = "Admin",
            Email = seed!.AdminEmail,
            Username = "admin",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(seed.AdminPassword),
            Role = UserRole.Admin
        });
        await db.SaveChangesAsync();
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.UseAuthentication();
app.UseAuthorization();


// ==========================
// 📌 ENDPOINTS
// ==========================

// 1) Registro público (sempre Bettor)
app.MapPost("/auth/register", async (RegisterRequest req, AuthDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Email == req.Email || u.Username == req.Username))
        return Results.Conflict(new { message = "Email or username already in use" });

    var user = new User
    {
        Name = req.Name,
        Email = req.Email,
        Username = req.Username,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
        Role = UserRole.Bettor
    };
    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/users/{user.Id}", new { user.Id, user.Email, user.Username, role = user.Role.ToString() });
});

// 2) Login → devolve accessToken + refreshToken
app.MapPost("/auth/login", async (LoginRequest req, AuthDbContext db, JwtTokenService jwt, JwtOptions jwtOpts) =>
{
    var user = await db.Users
        .FirstOrDefaultAsync(u => u.Email == req.UsernameOrEmail || u.Username == req.UsernameOrEmail);

    if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
        return Results.Unauthorized();

    var access = jwt.CreateAccessToken(user);

    // Refresh token seguro: ID + segredo
    var tokenId = Guid.NewGuid();
    var secret  = Guid.NewGuid().ToString("N");
    var refreshComposite = $"{tokenId:N}.{secret}";

    db.RefreshTokens.Add(new RefreshToken
    {
        Id        = tokenId,
        UserId    = user.Id,
        TokenHash = BCrypt.Net.BCrypt.HashPassword(secret),
        ExpiresAt = DateTime.UtcNow.AddDays(jwtOpts.RefreshTokenDays)
    });
    await db.SaveChangesAsync();

    return Results.Ok(new AuthResponse(access, refreshComposite));
});

// 3) Refresh → recebe refreshToken e devolve novo accessToken
app.MapPost("/auth/refresh", async (string refreshToken, AuthDbContext db, JwtTokenService jwt) =>
{
    if (string.IsNullOrWhiteSpace(refreshToken)) return Results.Unauthorized();

    var parts = refreshToken.Split('.', 2);
    if (parts.Length != 2) return Results.Unauthorized();

    if (!Guid.TryParseExact(parts[0], "N", out var tokenId)) return Results.Unauthorized();
    var secret = parts[1];

    var record = await db.RefreshTokens
        .Include(r => r.User)
        .FirstOrDefaultAsync(r => r.Id == tokenId);

    if (record is null || record.RevokedAt != null || record.ExpiresAt < DateTime.UtcNow)
        return Results.Unauthorized();

    if (!BCrypt.Net.BCrypt.Verify(secret, record.TokenHash))
        return Results.Unauthorized();

    var newAccess = jwt.CreateAccessToken(record.User);
    return Results.Ok(new { accessToken = newAccess });
});

// 4) Me → retorna dados do usuário autenticado
app.MapGet("/auth/me", async (ClaimsPrincipal principal, AuthDbContext db) =>
{
    var sub = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (sub is null) return Results.Unauthorized();

    var id = Guid.Parse(sub);
    var u = await db.Users.FindAsync(id);
    if (u is null) return Results.NotFound();

    return Results.Ok(new { u.Id, u.Email, u.Username, role = u.Role.ToString(), u.CreatedAt });
}).RequireAuthorization();

// 5) Criar Organizer (somente Admin)
app.MapPost("/admin/users/organizer", async (CreateOrganizerRequest req, AuthDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Email == req.Email || u.Username == req.Username))
        return Results.Conflict(new { message = "Email or username already in use" });

    var user = new User
    {
        Name = req.Name,
        Email = req.Email,
        Username = req.Username,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
        Role = UserRole.Organizer
    };
    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/users/{user.Id}", new { user.Id, user.Email, user.Username, role = user.Role.ToString() });
}).RequireAuthorization("AdminOnly");

app.Run();
