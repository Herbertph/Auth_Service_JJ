using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Dtos;
using FluentAssertions;
using Xunit;

namespace AuthService.Tests;

public class AuthFlowTests : IClassFixture<TestAppFactory>
{
    private readonly TestAppFactory _factory;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    public AuthFlowTests(TestAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Login_E_Me_Funcionam()
    {
        var client = _factory.CreateClient();

        var login = new LoginRequest("user@test.local", "P@ssw0rd!");
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", login);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var payload = await resp.Content.ReadFromJsonAsync<AuthResponse>(_json);
        payload.Should().NotBeNull();
        payload!.accessToken.Should().NotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", payload.accessToken);

        var me = await client.GetAsync("/api/v1/auth/me");
        me.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Refresh_Rotaciona_Revoga_Anterior()
    {
        var client = _factory.CreateClient();

        // login
        var login = new LoginRequest("user@test.local", "P@ssw0rd!");
        var resp = await client.PostAsJsonAsync("/api/v1/auth/login", login);
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var tokens = await resp.Content.ReadFromJsonAsync<AuthResponse>(_json);
        tokens.Should().NotBeNull();

        // refresh 1
        var refreshBody = JsonContent.Create(new { refreshToken = tokens!.refreshToken });
        var r1 = await client.PostAsync("/api/v1/auth/refresh", refreshBody);
        r1.StatusCode.Should().Be(HttpStatusCode.OK);

        var r1Json = await r1.Content.ReadFromJsonAsync<Dictionary<string, string>>(_json);
        r1Json.Should().ContainKeys("accessToken", "refreshToken");

        // refresh antigo deve falhar
        var rOld = await client.PostAsync(
            "/api/v1/auth/refresh",
            JsonContent.Create(new { refreshToken = tokens.refreshToken })
        );
        rOld.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Logout_Revoga_Apenas_Token_Do_Usuario()
    {
        var client = _factory.CreateClient();

        // login do user teste
        var resp = await client.PostAsJsonAsync(
            "/api/v1/auth/login",
            new LoginRequest("user@test.local", "P@ssw0rd!")
        );
        resp.StatusCode.Should().Be(HttpStatusCode.OK);

        var tokens = await resp.Content.ReadFromJsonAsync<AuthResponse>(_json);
        tokens.Should().NotBeNull();

        // autentica com access
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokens!.accessToken);

        // logout
        var r = await client.PostAsync(
            "/api/v1/auth/logout",
            JsonContent.Create(new { refreshToken = tokens.refreshToken })
        );
        r.StatusCode.Should().Be(HttpStatusCode.OK);

        // tentar refresh com o mesmo -> 401
        var r2 = await client.PostAsync(
            "/api/v1/auth/refresh",
            JsonContent.Create(new { refreshToken = tokens.refreshToken })
        );
        r2.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Me_Sem_Bearer_Deve_Ser_401()
    {
        var client = _factory.CreateClient();
        var me = await client.GetAsync("/api/v1/auth/me");
        me.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }
}
