using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Models
{
  public class VerifyMfaRequest
  {
    [Required]
    public string Code { get; set; }

    [Required]
    public string MfaToken { get; set; }
  }
}
