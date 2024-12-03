namespace AuthenticationService.Services
{
  public interface IEmailService
  {
    Task SendPasswordResetEmailAsync(string email, string callbackUrl);
  }

}