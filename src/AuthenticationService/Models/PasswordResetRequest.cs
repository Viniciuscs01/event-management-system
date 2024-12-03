using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Models
{
  public class PasswordResetRequest
  {
    [Required]
    [EmailAddress]
    public string Email { get; set; }
  }
}