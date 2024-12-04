namespace AuthenticationService.Services
{
    public interface IAuditLogService
    {
        Task LogOperationAsync(string? userId, string action);
    }
}
