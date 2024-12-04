using System.Diagnostics;
using System.Security.Claims;
using AuthenticationService.Data;
using AuthenticationService.Models;

namespace AuthenticationService.Middlewares;
public class AuditLoggingMiddleware
{
  private readonly RequestDelegate _next;
  private static readonly HashSet<string> ExcludedPaths = new()
    {
        "/swagger",
        "/api/auth/login",
        "/health"
    };

  public AuditLoggingMiddleware(RequestDelegate next)
  {
    _next = next;
  }

  public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext)
  {
    if (ExcludedPaths.Contains(context.Request.Path.Value))
    {
      await _next(context);
      return;
    }

    var stopwatch = Stopwatch.StartNew();

    try
    {
      await _next(context);
    }
    finally
    {
      stopwatch.Stop();

      var auditLog = new OperationAudit
      {
        UserId = context.User.FindFirstValue(ClaimTypes.NameIdentifier),
        Timestamp = DateTime.UtcNow,
        IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
        HttpMethod = context.Request.Method,
        Path = context.Request.Path,
        StatusCode = context.Response.StatusCode,
        ExecutionTime = stopwatch.ElapsedMilliseconds
      };

      dbContext.OperationAudits.Add(auditLog);
      await dbContext.SaveChangesAsync();
    }
  }
}
