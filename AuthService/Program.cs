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
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ---------- DbContext ----------
var conn = builder.Configuration.GetConnectionString("Default")
           ?? builder.Configuration["ConnectionStrings:Default"];
builder.Services.AddDbContext<AuthDbContext>(opt => opt.UseNpgsql(conn));

// ---------- Options ----------
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<SeedOptions>(builder.Configuration.GetSection("Seed"));

// Bind imediato para usar já na config do Auth (mantém também no DI)
var jwtOpts = builder.Configuration.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();

// Validação de chave (HS256 exige >= 32 bytes)
var keyText = jwtOpts.Key ?? string.Empty;
var keyBytes = Encoding.UTF8.GetBytes(keyText);
if (keyBytes.Length < 32)
{
    throw new InvalidOperationException(
        $"JWT key too short ({keyBytes.Length} bytes). Set 'Jwt__Key' env var with >= 32 bytes.");
}
var signingKey = new SymmetricSecurityKey(keyBytes);

// ---------- AuthN ----------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(opt =>
  {
      opt.RequireHttpsMetadata = false; // ok para DEV; em PROD use true por padrão
      opt.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = signingKey,

          // Valida Issuer/Audience somente se fornecidos
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
    opts.AddPolicy("dev", p => p
        .AllowAnyOrigin()
        .AllowAnyHeader()
        .AllowAnyMethod());
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
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [ jwtScheme ] = Array.Empty<string>()
    });
});

builder.Services.AddSingleton(jwtOpts);          // para injeção direta de JwtOptions
builder.Services.AddSingleton<JwtTokenService>();

var app = builder.Build();

// ---------- DB bootstrap (EnsureCreated para destravar agora) ----------
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

    // Para DEV inicial. Depois trocar por: await db.Database.MigrateAsync();
    await db.Database.EnsureCreatedAsync();

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

// ---------- Endpoints ----------
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

app.MapPost("/auth/login", async (LoginRequest req, AuthDbContext db, JwtTokenService jwt, JwtOptions jwtOptsInjected) =>
{
    var user = await db.Users
        .FirstOrDefaultAsync(u => u.Email == req.UsernameOrEmail || u.Username == req.UsernameOrEmail);

    if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
        return Results.Unauthorized();

    var access = jwt.CreateAccessToken(user);

    // Refresh token: ID + segredo (hash guardado no banco)
    var tokenId = Guid.NewGuid();
    var secret  = Guid.NewGuid().ToString("N");
    var refreshComposite = $"{tokenId:N}.{secret}";

    db.RefreshTokens.Add(new RefreshToken
    {
        Id        = tokenId,
        UserId    = user.Id,
        TokenHash = BCrypt.Net.BCrypt.HashPassword(secret),
        ExpiresAt = DateTime.UtcNow.AddDays(jwtOptsInjected.RefreshTokenDays)
    });
    await db.SaveChangesAsync();

    return Results.Ok(new AuthResponse(access, refreshComposite));
});

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

app.MapGet("/auth/me", async (ClaimsPrincipal principal, AuthDbContext db) =>
{
    var sub = principal.FindFirstValue("sub") ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (sub is null) return Results.Unauthorized();

    var id = Guid.Parse(sub);
    var u = await db.Users.FindAsync(id);
    if (u is null) return Results.NotFound();

    return Results.Ok(new { u.Id, u.Email, u.Username, role = u.Role.ToString(), u.CreatedAt });
}).RequireAuthorization();

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
