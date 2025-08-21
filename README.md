# Auth_Service_JJ

Auth Service for BJJ BET

## Overview

This project is an authentication microservice built with ASP.NET Core 8 and Entity Framework Core, using PostgreSQL as the database. It provides user registration, login, JWT-based authentication, and role-based authorization.

## Features

- User registration and login
- JWT token generation and validation
- Refresh token support
- Role-based authorization (Admin, User, etc.)
- Health and readiness endpoints
- Swagger/OpenAPI documentation
- Docker support

## Project Structure

```
Auth_Service_JJ.sln
AuthService/
  Program.cs
  Data/
    AuthDbContext.cs
  Domain/
    Entities/
      User.cs
      RefreshToken.cs
    Enums/
      UserRole.cs
  Dtos/
    AuthDtos.cs
  Options/
    JwtOptions.cs
    SeedOptions.cs
  Services/
    JwtokenService.cs
  Migrations/
  appsettings.json
  appsettings.Development.json
  Dockerfile
  docker-compose.yml
tests/
  AuthService.Tests/
    AuthFlowTests.cs
    JwtTokenServiceTests.cs
    TestAppFactory.cs
```

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [PostgreSQL](https://www.postgresql.org/) (or use Docker)
- [Docker](https://www.docker.com/) (optional, for containerization)

### Configuration

Edit `AuthService/appsettings.json` and `appsettings.Development.json` to set your database connection string and JWT settings.

Example:
```json
"ConnectionStrings": {
  "DefaultConnection": "Host=localhost;Database=authdb;Username=postgres;Password=yourpassword"
},
"Jwt": {
  "Key": "your_secret_key",
  "Issuer": "your_issuer",
  "Audience": "your_audience",
  "ExpiresInMinutes": 60
}
```

### Database Migration

Apply migrations to set up the database schema:

```sh
cd AuthService
dotnet ef database update
```

### Running the Service

#### Locally

```sh
dotnet run --project AuthService
```

The API will be available at `https://localhost:5001` or `http://localhost:5000`.

#### With Docker

Build and run using Docker Compose:

```sh
docker-compose up --build
```

### API Documentation

Swagger UI is available in development mode at:

```
http://localhost:5000/swagger
```

### Health Checks

- `GET /health` — Returns service status
- `GET /ready` — Checks database connectivity

### Testing

Unit and integration tests are located in `tests/AuthService.Tests`.

Run tests with:

```sh
dotnet test
```

## Main Endpoints

- `POST /api/v1/auth/register` — Register a new user
- `POST /api/v1/auth/login` — Login and receive JWT
- `POST /api/v1/auth/refresh` — Refresh JWT token
- `POST /api/v1/auth/logout` — Logout and revoke refresh token
- `GET /api/v1/auth/me` — Get current user info (requires authentication)

## Environment Variables

You can override configuration using environment variables, especially for Docker deployments.

## License

MIT License

---