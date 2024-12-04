using AuthenticationService.Data;
using AuthenticationService.Models;

namespace AuthenticationService.Services
{
  public class AuditLogService : IAuditLogService
  {
    private readonly ApplicationDbContext _dbContext;

    public AuditLogService(ApplicationDbContext dbContext)
    {
      _dbContext = dbContext;
    }

    public async Task LogOperationAsync(string? userId, string action)
    {
      var auditLog = new OperationAudit
      {
        UserId = userId,
        Timestamp = DateTime.UtcNow,
        IpAddress = "N/A",
        HttpMethod = "N/A",
        Path = action,
        StatusCode = 0,
        ExecutionTime = 0,
        Details = action
      };

      _dbContext.OperationAudits.Add(auditLog);
      await _dbContext.SaveChangesAsync();
    }
  }
}
