using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthenticationService.Models;
using AuthenticationService.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OtpNet;

namespace AuthenticationService.Tests.Controllers
{
  public class AuthControllerTests : IClassFixture<WebApplicationFactory<Program>>
  {
    private readonly HttpClient _client;
    private readonly WebApplicationFactory<Program> _factory;
    private readonly Mock<IEmailService> _emailServiceMock;

    public AuthControllerTests(WebApplicationFactory<Program> factory)
    {
      _factory = factory;
      _client = factory.CreateClient();
      _emailServiceMock = new Mock<IEmailService>();
    }

    [Fact]
    public async Task HealthCheck_ShouldReturnSuccess()
    {
      // Act
      var response = await _client.GetAsync("/api/health");

      // Assert
      response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Register_ShouldReturnSuccess_WhenValidRequest()
    {
      // Arrange
      var uniqueEmail = $"testuser-{Guid.NewGuid()}@example.com";
      var request = new RegisterRequest
      {
        Email = uniqueEmail,
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/register", request);

      // Assert
      var content = await response.Content.ReadFromJsonAsync<JsonElement>();
      var message = content.GetProperty("message").GetString();

      Assert.Equal("User registered successfully!", message);
    }

    [Fact]
    public async Task Register_ShouldReturnBadRequest_WhenEmailAlreadyExists()
    {
      // Arrange
      var request = new RegisterRequest
      {
        Email = "duplicate@example.com",
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      // Primeiro registro
      await _client.PostAsJsonAsync("/api/auth/register", request);

      // Segundo registro com o mesmo e-mail
      var response = await _client.PostAsJsonAsync("/api/auth/register", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

      var content = await response.Content.ReadFromJsonAsync<JsonElement>();
      var description = content[0].GetProperty("description").GetString();
      Assert.Contains("is already taken", description);
    }

    [Fact]
    public async Task Register_ShouldReturnBadRequest_WhenPasswordsDoNotMatch()
    {
      // Arrange
      var request = new RegisterRequest
      {
        Email = "mismatch@example.com",
        Password = "Password123!",
        ConfirmPassword = "DifferentPassword!"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/register", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

      var content = await response.Content.ReadFromJsonAsync<JsonElement>();

      // Acessar a mensagem de erro dentro de "errors"
      var errors = content.GetProperty("errors");
      var confirmPasswordErrors = errors.GetProperty("ConfirmPassword").EnumerateArray();
      var errorMessage = confirmPasswordErrors.First().GetString();

      Assert.Equal("Passwords do not match.", errorMessage);
    }

    [Fact]
    public async Task Register_ShouldReturnBadRequest_WhenEmailIsInvalid()
    {
      // Arrange
      var request = new RegisterRequest
      {
        Email = "invalid-email",
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/register", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

      // Parse JSON response
      var content = await response.Content.ReadFromJsonAsync<JsonElement>();
      var errors = content.GetProperty("errors");
      var emailErrors = errors.GetProperty("Email").EnumerateArray();
      var errorMessage = emailErrors.First().GetString();

      Assert.Equal("The Email field is not a valid e-mail address.", errorMessage);
    }

    [Fact]
    public async Task Login_ShouldReturnMfaSetup_WhenMfaNotConfigured()
    {
      // Arrange
      var registerRequest = new RegisterRequest
      {
        Email = $"newuser-{Guid.NewGuid()}@example.com",
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      var loginRequest = new LoginRequest
      {
        Email = registerRequest.Email,
        Password = registerRequest.Password
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.OK);

      var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
      result.Should().NotBeNull();
      result.RequiresMfa.Should().BeTrue();
      result.QrCode.Should().NotBeNull();
      result.Secret.Should().NotBeNull();
    }

    [Fact]
    public async Task Login_ShouldReturnTemporaryToken_WhenMfaConfigured()
    {
      // Arrange
      var email = $"userwithmfa-{Guid.NewGuid()}@example.com";
      var password = "Password123!";

      var registerRequest = new RegisterRequest
      {
        Email = email,
        Password = password,
        ConfirmPassword = password
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      var user = await GetUserByEmailAsync(email);
      await ConfigureMfaForUserAsync(user);

      var loginRequest = new LoginRequest
      {
        Email = email,
        Password = password
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.OK);

      var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
      result.Should().NotBeNull();
      result.RequiresMfa.Should().BeTrue();
      result.Token.Should().NotBeNull();
    }


    [Fact]
    public async Task Login_ShouldReturnUnauthorized_WhenEmailDoesNotExist()
    {
      // Arrange
      var loginRequest = new LoginRequest
      {
        Email = "nonexistent@example.com",
        Password = "Password123!"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
      var result = await response.Content.ReadAsStringAsync();
      result.Should().Contain("Invalid email or password.");
    }

    [Fact]
    public async Task Login_ShouldReturnUnauthorized_WhenPasswordIsIncorrect()
    {
      // Arrange
      var registerRequest = new RegisterRequest
      {
        Email = "testuser2@example.com",
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      var loginRequest = new LoginRequest
      {
        Email = registerRequest.Email,
        Password = "WrongPassword!"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
      var result = await response.Content.ReadAsStringAsync();
      result.Should().Contain("Invalid email or password.");
    }

    [Fact]
    public async Task EnableMfa_ShouldReturnQrCode_WhenUserExists()
    {
      // Arrange
      var registerRequest = new RegisterRequest
      {
        Email = "mfauser@example.com",
        Password = "Password123!",
        ConfirmPassword = "Password123!"
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      var user = await GetUserByEmailAsync(registerRequest.Email);

      var enableMfaRequest = new EnableMfaRequest
      {
        UserId = user.Id
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/mfa/enable", enableMfaRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.OK);

      var result = await response.Content.ReadFromJsonAsync<JsonElement>();

      var secret = result.GetProperty("secret").GetString();
      var qrCode = result.GetProperty("qrCode").GetString();

      Assert.NotNull(secret);
      Assert.NotNull(qrCode);
    }

    [Fact]
    public async Task EnableMfa_ShouldReturnNotFound_WhenUserDoesNotExist()
    {
      // Arrange
      var enableMfaRequest = new EnableMfaRequest
      {
        UserId = "nonexistent-user-id"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/mfa/enable", enableMfaRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.NotFound);
      var result = await response.Content.ReadAsStringAsync();
      result.Should().Contain("User not found.");
    }

    [Fact]
    public async Task ValidateMfa_ShouldReturnJwtToken_WhenMfaIsValid()
    {
      // Arrange
      var email = "validateuser@example.com";
      var password = "Password123!";

      var registerRequest = new RegisterRequest
      {
        Email = email,
        Password = password,
        ConfirmPassword = password
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      // Simular a configuração do MFA
      var user = await GetUserByEmailAsync(email);
      await ConfigureMfaForUserAsync(user);

      // Realizar login para obter o token temporário
      var loginRequest = new LoginRequest
      {
        Email = email,
        Password = password
      };
      var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
      var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

      // Obter o código TOTP dentro de um escopo
      string secret;
      using (var scope = _factory.Services.CreateScope())
      {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        var refreshedUser = await userManager.FindByEmailAsync(email); // Recarrega o usuário para evitar problemas de tracking
        secret = await userManager.GetAuthenticationTokenAsync(refreshedUser, "MFA", "Secret");
      }

      var totp = new Totp(Base32Encoding.ToBytes(secret));
      var code = totp.ComputeTotp();

      var validateMfaRequest = new VerifyMfaRequest
      {
        Code = code,
        MfaToken = loginResult.Token
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/mfa/validate", validateMfaRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.OK);
      var result = await response.Content.ReadFromJsonAsync<JsonElement>();
      var token = result.GetProperty("token").GetString();
      Assert.NotNull(token);
    }

    [Fact]
    public async Task ValidateMfa_ShouldReturnUnauthorized_WhenMfaCodeIsInvalid()
    {
      // Arrange
      var email = "invalidmfacode@example.com";
      var password = "Password123!";

      var registerRequest = new RegisterRequest
      {
        Email = email,
        Password = password,
        ConfirmPassword = password
      };

      await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

      var user = await GetUserByEmailAsync(email);
      await ConfigureMfaForUserAsync(user);

      var loginRequest = new LoginRequest
      {
        Email = email,
        Password = password
      };
      var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
      var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

      var validateMfaRequest = new VerifyMfaRequest
      {
        Code = "000000", // Código inválido
        MfaToken = loginResult.Token
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/mfa/validate", validateMfaRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
      var result = await response.Content.ReadAsStringAsync();
      result.Should().Contain("Invalid MFA code.");
    }

    [Fact]
    public async Task ValidateMfa_ShouldReturnUnauthorized_WhenMfaTokenIsInvalid()
    {
      // Arrange
      var validateMfaRequest = new VerifyMfaRequest
      {
        Code = "123456",
        MfaToken = "invalid-token"
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/mfa/validate", validateMfaRequest);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
      var result = await response.Content.ReadAsStringAsync();
      result.Should().Contain("Invalid or expired MFA token.");
    }

    [Fact]
    public async Task RequestPasswordReset_ShouldSendEmail_WhenEmailExists()
    {
      // Arrange
      var email = "user@example.com";
      var user = new IdentityUser { UserName = email, Email = email };

      using (var scope = _factory.Services.CreateScope())
      {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        await userManager.CreateAsync(user, "Password123!");
      }

      var request = new PasswordResetRequest { Email = email };

      _emailServiceMock
          .Setup(e => e.SendPasswordResetEmailAsync(email, It.IsAny<string>()))
          .Returns(Task.CompletedTask);

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/password/reset/request", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.OK);
      //_emailServiceMock.Verify(e => e.SendPasswordResetEmailAsync(email, It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task RequestPasswordReset_ShouldReturnNotFound_WhenEmailDoesNotExist()
    {
      // Arrange
      var request = new PasswordResetRequest { Email = "nonexistent@example.com" };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/password/reset/request", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ConfirmPasswordReset_ShouldReturnBadRequest_WhenTokenIsInvalid()
    {
      // Arrange
      var email = "userinvalidtoken@example.com";
      var user = new IdentityUser { UserName = email, Email = email };
      var invalidToken = "invalid-token";
      var newPassword = "Password123!";

      using (var scope = _factory.Services.CreateScope())
      {
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
        await userManager.CreateAsync(user, "Password123!");
      }

      var request = new PasswordResetConfirmation
      {
        Email = email,
        Token = invalidToken,
        NewPassword = newPassword
      };

      // Act
      var response = await _client.PostAsJsonAsync("/api/auth/password/reset/confirm", request);

      // Assert
      response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    private async Task<IdentityUser> GetUserByEmailAsync(string email)
    {
      using var scope = _factory.Services.CreateScope();
      var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
      return await userManager.FindByEmailAsync(email);
    }

    private async Task ConfigureMfaForUserAsync(IdentityUser user)
    {
      using var scope = _factory.Services.CreateScope();
      var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

      // Recarregar o usuário do banco para evitar conflitos de rastreamento
      var existingUser = await userManager.FindByIdAsync(user.Id);

      var key = KeyGeneration.GenerateRandomKey(20);
      var base32Secret = Base32Encoding.ToString(key);

      existingUser.TwoFactorEnabled = true;
      await userManager.SetAuthenticationTokenAsync(existingUser, "MFA", "Secret", base32Secret);
    }
  }
}
