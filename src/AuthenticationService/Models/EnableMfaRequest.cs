using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Models
{
    public class EnableMfaRequest
    {
        [Required]
        public string UserId { get; set; }
    }
}
