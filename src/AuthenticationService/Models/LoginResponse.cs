namespace AuthenticationService.Models
{
  public class LoginResponse
  {
    public bool RequiresMfa { get; set; }
    public string? QrCode { get; set; }
    public string? Secret { get; set; }
    public string? Token { get; set; }
  }
}