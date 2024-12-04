using System.Text;
using AuthenticationService.Data;
using AuthenticationService.Middlewares;
using AuthenticationService.Services;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

public partial class Program
{
  public static void Main(string[] args)
  {
    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    var keyVaultName = builder.Configuration["KeyVaultName"];
    if (!string.IsNullOrEmpty(keyVaultName))
    {
      var uri = new Uri($"https://{keyVaultName}.vault.azure.net/");
      var clientId = builder.Configuration["AzureAD:ClientId"];
      var clientSecret = builder.Configuration["AzureAD:ClientSecret"];
      var tenantId = builder.Configuration["AzureAD:TenantId"];

      builder.Configuration.AddAzureKeyVault(uri, new ClientSecretCredential(tenantId, clientId, clientSecret));
    }

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(builder.Configuration["EMS:ConnectionStrings:DefaultConnection"]));

    builder.Services.AddIdentity<IdentityUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    var jwtSecret = builder.Configuration["EMS:JWT:SECRET"];
    if (string.IsNullOrEmpty(jwtSecret))
      throw new InvalidOperationException("EMS:JWT:SECRET is not configured.");

    var key = Encoding.ASCII.GetBytes(jwtSecret);

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
          options.TokenValidationParameters = new TokenValidationParameters
          {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key)
          };
        });

    builder.Services.Configure<IdentityOptions>(options =>
    {
      options.Password.RequireDigit = true;
      options.Password.RequiredLength = 8;
      options.Password.RequireNonAlphanumeric = false;
      options.Password.RequireUppercase = true;
      options.Password.RequireLowercase = true;

      options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
      options.Lockout.MaxFailedAccessAttempts = 5;
      options.Lockout.AllowedForNewUsers = true;

      options.User.RequireUniqueEmail = true;
    });

    builder.Services.AddAuthorization();

    builder.Services.AddControllers();

    builder.Services.AddScoped<IEmailService, EmailService>();
    builder.Services.AddScoped<IAuditLogService, AuditLogService>();


    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
      app.UseSwagger();
      app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.UseMiddleware<AuditLoggingMiddleware>();

    app.Run();
  }
}

