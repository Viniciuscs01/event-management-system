using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Models
{
    public class VerifyMfaRequest
    {
        [Required]
        public string UserId { get; set; }

        [Required]
        public string Code { get; set; }
    }
}
