using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OtpNet;

namespace AuthenticationService.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration) : ControllerBase
  {
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly IConfiguration _configuration = configuration;

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

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = await _userManager.FindByEmailAsync(request.Email);
      if (user == null)
        return Unauthorized("Invalid email or password.");

      var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
      if (!result.Succeeded)
        return Unauthorized("Invalid email or password.");

      var token = GenerateJwtToken(user);
      return Ok(new { Token = token });
    }

    [HttpPost("mfa/enable")]
    public async Task<IActionResult> EnableMfa([FromBody] EnableMfaRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = await _userManager.FindByIdAsync(request.UserId);
      if (user == null)
        return NotFound("User not found.");

      var key = KeyGeneration.GenerateRandomKey(20);
      var base32Secret = Base32Encoding.ToString(key);

      user.TwoFactorEnabled = true;
      await _userManager.SetAuthenticationTokenAsync(user, "MFA", "Secret", base32Secret);

      var qrCode = $"otpauth://totp/AuthenticationService:{user.Email}?secret={base32Secret}&issuer=AuthenticationService";

      return Ok(new { Secret = base32Secret, QrCode = qrCode });
    }

    [HttpPost("mfa/verify")]
    public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = await _userManager.FindByIdAsync(request.UserId);
      if (user == null)
        return NotFound("User not found.");

      var secret = await _userManager.GetAuthenticationTokenAsync(user, "MFA", "Secret");
      if (string.IsNullOrEmpty(secret))
        return BadRequest("MFA is not enabled for this user.");

      var totp = new Totp(Base32Encoding.ToBytes(secret));
      var isValid = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

      if (!isValid)
        return Unauthorized("Invalid MFA code.");

      return Ok(new { Message = "MFA verified successfully!" });
    }

    private string GenerateJwtToken(IdentityUser user)
    {
      var claims = new[]
      {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["EMS:JWT:SECRET"]));
      var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

      var token = new JwtSecurityToken(
          issuer: null,
          audience: null,
          claims: claims,
          expires: DateTime.UtcNow.AddHours(1),
          signingCredentials: creds
      );

      return new JwtSecurityTokenHandler().WriteToken(token);
    }
  }
}
