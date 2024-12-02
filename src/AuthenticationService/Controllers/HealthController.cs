using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers
{
  [ApiController]
  [Route("api/health")]
  public class HealthController : ControllerBase
  {
    [HttpGet]
    public IActionResult Get()
    {
      return Ok("API is running.");
    }
  }
}