using System.Net;
using System.Net.Mail;

namespace AuthenticationService.Services
{
  public class EmailService : IEmailService
  {
    private readonly IConfiguration _configuration;

    public EmailService(IConfiguration configuration)
    {
      _configuration = configuration;
    }

    public async Task SendPasswordResetEmailAsync(string email, string callbackUrl)
    {
      // Exemplo com SMTP
      using var client = new SmtpClient
      {
        Host = _configuration["Smtp:Host"],
        Port = int.Parse(_configuration["Smtp:Port"]),
        Credentials = new NetworkCredential(_configuration["Smtp:User"], _configuration["Smtp:Password"]),
        EnableSsl = true
      };

      var mailMessage = new MailMessage
      {
        From = new MailAddress(_configuration["Smtp:From"]),
        Subject = "Password Reset",
        Body = $"Reset your password by clicking <a href='{callbackUrl}'>here</a>.",
        IsBodyHtml = true
      };

      mailMessage.To.Add(email);
      await client.SendMailAsync(mailMessage);
    }
  }
}