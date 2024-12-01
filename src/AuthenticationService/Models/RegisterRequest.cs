using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Models
{
  public class RegisterRequest
  {
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [MinLength(8)]
    public string Password { get; set; }

    [Required]
    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public string ConfirmPassword { get; set; }
  }
}
