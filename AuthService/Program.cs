using System.Security.Claims;
using System.Text;
using AuthService;
using AuthService.Data;
using AuthService.Domain.Entities;
using AuthService.Domain.Enums;
using AuthService.Dtos;
using AuthService.Options;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ---------- DbContext ----------
var conn = builder.Configuration.GetConnectionString("Default")
           ?? builder.Configuration["ConnectionStrings:Default"];
builder.Services.AddDbContext<AuthDbContext>(opt => opt.UseNpgsql(conn));

// ---------- Options ----------
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<SeedOptions>(builder.Configuration.GetSection("Seed"));
var jwtOpts = builder.Configuration.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();

// ---------- JWT Key (HS256 >= 32 bytes) ----------
var keyText = jwtOpts.Key ?? string.Empty;
var keyBytes = Encoding.UTF8.GetBytes(keyText);
if (keyBytes.Length < 32)
    throw new InvalidOperationException($"JWT key too short ({keyBytes.Length} bytes). Set 'Jwt__Key' with >= 32 bytes.");
var signingKey = new SymmetricSecurityKey(keyBytes);

// ---------- AuthN ----------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(opt =>
  {
      opt.RequireHttpsMetadata = !builder.Environment.IsDevelopment(); // HTTPS em prod
      opt.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = signingKey,

          ValidateIssuer = !string.IsNullOrWhiteSpace(jwtOpts.Issuer),
          ValidIssuer = jwtOpts.Issuer,

          ValidateAudience = !string.IsNullOrWhiteSpace(jwtOpts.Audience),
          ValidAudience = jwtOpts.Audience,

          ValidateLifetime = true,
          ClockSkew = TimeSpan.FromSeconds(30)
      };
  });

// ---------- AuthZ ----------
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("AdminOnly", p => p.RequireRole(UserRole.Admin.ToString()));
    opts.AddPolicy("OrganizerOrAdmin", p => p.RequireRole(UserRole.Organizer.ToString(), UserRole.Admin.ToString()));
});

// ---------- CORS (dev) ----------
builder.Services.AddCors(opts =>
{
    opts.AddPolicy("dev", p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

// ---------- Swagger ----------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JJ Arena Auth", Version = "v1" });
    var jwtScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Informe: Bearer {seu_token}"
    };
    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement { [ jwtScheme ] = Array.Empty<string>() });
});

builder.Services.AddSingleton(jwtOpts);          // para DI direto
builder.Services.AddSingleton<JwtTokenService>();

var app = builder.Build();

// ---------- DB bootstrap ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.MigrateAsync(); // aplica migrações

    // seed admin (somente se não existir)
    var seed = app.Configuration.GetSection("Seed").Get<SeedOptions>();
    if (!string.IsNullOrWhiteSpace(seed?.AdminEmail) &&
        !await db.Users.AnyAsync(u => u.Email == seed.AdminEmail))
    {
        db.Users.Add(new User
        {
            Name = "Admin",
            Email = seed.AdminEmail!,
            Username = "admin",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(seed.AdminPassword),
            Role = UserRole.Admin
        });
        await db.SaveChangesAsync();
    }
}

// ---------- Middlewares ----------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseCors("dev");
app.UseAuthentication();
app.UseAuthorization();

// ---------- Health ----------
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapGet("/ready", async (AuthDbContext db) =>
{
    var canQuery = await db.Database.CanConnectAsync();
    return canQuery ? Results.Ok(new { ready = true }) : Results.StatusCode(503);
});

// ---------- API v1 ----------
var api = app.MapGroup("/api/v1");

// -------- Auth endpoints --------
api.MapPost("/auth/register", async (RegisterRequest req, AuthDbContext db) =>
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

    return Results.Created($"/api/v1/users/{user.Id}", new { user.Id, user.Email, user.Username, role = user.Role.ToString() });
});

api.MapPost("/auth/login", async (LoginRequest req, AuthDbContext db, JwtTokenService jwt, JwtOptions injected) =>
{
    var user = await db.Users
        .FirstOrDefaultAsync(u => u.Email == req.UsernameOrEmail || u.Username == req.UsernameOrEmail);

    if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
        return Results.Unauthorized();

    var access = jwt.CreateAccessToken(user);

    // Refresh token: ID + segredo (hash guardado no banco)
    var tokenId = Guid.NewGuid();
    var secret  = Guid.NewGuid().ToString("N");
    var composite = $"{tokenId:N}.{secret}";

    db.RefreshTokens.Add(new RefreshToken
    {
        Id        = tokenId,
        UserId    = user.Id,
        TokenHash = BCrypt.Net.BCrypt.HashPassword(secret),
        ExpiresAt = DateTime.UtcNow.AddDays(injected.RefreshTokenDays)
    });
    await db.SaveChangesAsync();

    return Results.Ok(new AuthResponse(access, composite));
});

api.MapPost("/auth/refresh", async (string refreshToken, AuthDbContext db, JwtTokenService jwt, JwtOptions opts) =>
{
    if (string.IsNullOrWhiteSpace(refreshToken)) return Results.Unauthorized();

    var parts = refreshToken.Split('.', 2);
    if (parts.Length != 2) return Results.Unauthorized();
    if (!Guid.TryParseExact(parts[0], "N", out var tokenId)) return Results.Unauthorized();
    var secret = parts[1];

    var record = await db.RefreshTokens.Include(r => r.User).FirstOrDefaultAsync(r => r.Id == tokenId);
    if (record is null || record.RevokedAt != null || record.ExpiresAt < DateTime.UtcNow)
        return Results.Unauthorized();

    if (!BCrypt.Net.BCrypt.Verify(secret, record.TokenHash))
        return Results.Unauthorized();

    // ROTATION: revoga o atual e emite novo par
    record.RevokedAt = DateTime.UtcNow;

    var newAccess = jwt.CreateAccessToken(record.User);
    var newId = Guid.NewGuid();
    var newSecret = Guid.NewGuid().ToString("N");
    var newComposite = $"{newId:N}.{newSecret}";

    db.RefreshTokens.Add(new RefreshToken
    {
        Id        = newId,
        UserId    = record.UserId,
        TokenHash = BCrypt.Net.BCrypt.HashPassword(newSecret),
        ExpiresAt = DateTime.UtcNow.AddDays(opts.RefreshTokenDays)
    });

    await db.SaveChangesAsync();
    return Results.Ok(new { accessToken = newAccess, refreshToken = newComposite });
});

// revoga 1 sessão (precisa estar autenticado)
api.MapPost("/auth/logout", async (string refreshToken, AuthDbContext db) =>
{
    var parts = refreshToken.Split('.', 2);
    if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "N", out var tokenId)) return Results.Unauthorized();

    var rec = await db.RefreshTokens.FirstOrDefaultAsync(r => r.Id == tokenId);
    if (rec is not null && rec.RevokedAt is null) rec.RevokedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();
    return Results.Ok();
}).RequireAuthorization();

// revoga TODAS as sessões do usuário
api.MapPost("/auth/logout-all", async (ClaimsPrincipal principal, AuthDbContext db) =>
{
    var sub = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (sub is null) return Results.Unauthorized();

    var userId = Guid.Parse(sub);
    var tokens = await db.RefreshTokens.Where(r => r.UserId == userId && r.RevokedAt == null).ToListAsync();
    foreach (var t in tokens) t.RevokedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();
    return Results.Ok(new { revoked = tokens.Count });
}).RequireAuthorization();

// whoami
api.MapGet("/auth/me", async (ClaimsPrincipal principal, AuthDbContext db) =>
{
    var sub = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (sub is null) return Results.Unauthorized();

    var id = Guid.Parse(sub);
    var u = await db.Users.FindAsync(id);
    if (u is null) return Results.NotFound();

    return Results.Ok(new { u.Id, u.Email, u.Username, role = u.Role.ToString(), u.CreatedAt });
}).RequireAuthorization();

// -------- Admin / Roles test --------
api.MapPost("/admin/users/organizer", async (CreateOrganizerRequest req, AuthDbContext db) =>
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
    return Results.Created($"/api/v1/users/{user.Id}", new { user.Id, user.Email, user.Username, role = user.Role.ToString() });
}).RequireAuthorization("AdminOnly");

api.MapGet("/admin/ping", () => Results.Ok(new { ok = true })).RequireAuthorization("AdminOnly");
api.MapGet("/org/ping", () => Results.Ok(new { ok = true })).RequireAuthorization("OrganizerOrAdmin");

app.Run();

// Habilita WebApplicationFactory<> em testes
namespace AuthService { public partial class Program {} }
