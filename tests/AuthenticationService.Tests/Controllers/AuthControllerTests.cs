using System.Net.Http.Json;
using AuthenticationService.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AuthenticationService.Tests.Controllers
{
  public class AuthControllerTests : IClassFixture<WebApplicationFactory<Program>>
  {
    private readonly HttpClient _client;

    public AuthControllerTests(WebApplicationFactory<Program> factory)
    {
      _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthCheck_ShouldReturnSuccess()
    {
      // Act
      var response = await _client.GetAsync("/api/health");

      // Assert
      response.EnsureSuccessStatusCode();
    }
  }
}
