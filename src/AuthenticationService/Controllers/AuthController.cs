using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationService.Models;
using AuthenticationService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OtpNet;

namespace AuthenticationService.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration, IEmailService emailService) : ControllerBase
  {
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly IConfiguration _configuration = configuration;
    private readonly IEmailService _emailService = emailService;

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

      if (!user.TwoFactorEnabled)
      {
        var key = KeyGeneration.GenerateRandomKey(20);
        var base32Secret = Base32Encoding.ToString(key);

        user.TwoFactorEnabled = true;
        await _userManager.SetAuthenticationTokenAsync(user, "MFA", "Secret", base32Secret);

        var qrCode = $"otpauth://totp/AuthenticationService:{user.Email}?secret={base32Secret}&issuer=AuthenticationService";

        return Ok(new LoginResponse
        {
          RequiresMfa = true,
          QrCode = qrCode,
          Secret = base32Secret
        });
      }

      var rawToken = Guid.NewGuid().ToString();
      var hashedToken = BCrypt.Net.BCrypt.HashPassword(rawToken);

      await _userManager.SetAuthenticationTokenAsync(user, "MFA", "MfaTokenHash", hashedToken);

      return Ok(new LoginResponse
      {
        RequiresMfa = true,
        Token = rawToken
      });
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

    [HttpPost("mfa/validate")]
    public async Task<IActionResult> ValidateMfa([FromBody] VerifyMfaRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var users = await _userManager.Users.ToListAsync();

      IdentityUser? user = null;
      foreach (var u in users)
      {
        var storedTokenHash = await _userManager.GetAuthenticationTokenAsync(u, "MFA", "MfaTokenHash");
        if (!string.IsNullOrEmpty(storedTokenHash) && BCrypt.Net.BCrypt.Verify(request.MfaToken, storedTokenHash))
        {
          user = u;
          break;
        }
      }

      if (user == null)
        return Unauthorized("Invalid or expired MFA token.");

      var secret = await _userManager.GetAuthenticationTokenAsync(user, "MFA", "Secret");
      if (string.IsNullOrEmpty(secret))
      {
        return BadRequest("MFA is not configured for this user.");
      }

      var totp = new Totp(Base32Encoding.ToBytes(secret));
      var isValid = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
      if (!isValid)
      {
        return Unauthorized("Invalid MFA code.");
      }

      // Gerar JWT e invalidar o token temporário
      var token = GenerateJwtToken(user);
      await _userManager.RemoveAuthenticationTokenAsync(user, "MFA", "MfaTokenHash");

      return Ok(new { Token = token });
    }

    [HttpPost("password/reset/request")]
    public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequest request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = await _userManager.FindByEmailAsync(request.Email);
      if (user == null)
        return NotFound("User not found.");

      var token = await _userManager.GeneratePasswordResetTokenAsync(user);

      // Enviar token por e-mail
      var callbackUrl = $"{Request.Scheme}://{Request.Host}/reset-password?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(request.Email)}";
      await _emailService.SendPasswordResetEmailAsync(user.Email, callbackUrl);

      return Ok(new { Message = "Password reset link has been sent to your email." });
    }

    [HttpPost("password/reset/confirm")]
    public async Task<IActionResult> ConfirmPasswordReset([FromBody] PasswordResetConfirmation request)
    {
      if (!ModelState.IsValid)
        return BadRequest(ModelState);

      var user = await _userManager.FindByEmailAsync(request.Email);
      if (user == null)
        return NotFound("User not found.");

      var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

      if (!result.Succeeded)
        return BadRequest(result.Errors);

      return Ok(new { Message = "Password has been reset successfully." });
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
