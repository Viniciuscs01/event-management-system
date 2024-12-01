using System.Text;
using AuthenticationService.Data;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

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

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.Run();