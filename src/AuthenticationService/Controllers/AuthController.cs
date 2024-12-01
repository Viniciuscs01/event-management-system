using AuthenticationService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : ControllerBase
  {
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = new IdentityUser
      {
        UserName = request.Email,
        Email = request.Email
      };

      var result = await _userManager.CreateAsync(user, request.Password);
      if (!result.Succeeded)
        return BadRequest(result.Errors);

      return Ok(new { Message = "User registered successfully!" });
    }
  }
}
