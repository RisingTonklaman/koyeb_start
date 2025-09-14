using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Prometheus;
using Serilog;
using Serilog.Formatting.Compact;

var builder = WebApplication.CreateBuilder(args);

// ===== Config & Secrets =====
var dbUrl = Environment.GetEnvironmentVariable("DATABASE_URL") 
            ?? builder.Configuration.GetConnectionString("Default");
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? "dev-secret-change";
var allowOrigin = Environment.GetEnvironmentVariable("CORS_ORIGIN") ?? "*";

// ===== Logging: structured JSON =====
Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .WriteTo.Console(new CompactJsonFormatter())
    .CreateLogger();
builder.Host.UseSerilog();

// ===== DB =====
builder.Services.AddDbContext<AppDb>(opt => opt.UseNpgsql(dbUrl));

// ===== Auth (JWT) =====
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false, ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ClockSkew = TimeSpan.Zero
        };
    });
builder.Services.AddAuthorization();

// ===== Rate limit =====
builder.Services.AddRateLimiter(o =>
    o.AddFixedWindowLimiter("fixed", options =>
    {
        options.Window = TimeSpan.FromSeconds(10);
        options.PermitLimit = 100;
        options.QueueLimit = 0;
    }));

// ===== OpenAPI =====
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ===== CORS =====
builder.Services.AddCors(p => p.AddDefaultPolicy(policy =>
    policy.WithOrigins(allowOrigin == "*" ? Array.Empty<string>() : new[] { allowOrigin })
          .AllowAnyHeader()
          .AllowAnyMethod()
          .SetIsOriginAllowed(_ => allowOrigin == "*")));

// ===== Health checks & Metrics =====
builder.Services.AddHealthChecks().AddNpgSql(dbUrl, name: "postgres");

var app = builder.Build();

// Auto-migrate (ง่ายสำหรับเริ่มต้น)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDb>();
    db.Database.Migrate();
}

// ===== Middleware =====
app.UseSerilogRequestLogging();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseHttpMetrics();            // request metrics
app.UseSwagger();
app.UseSwaggerUI();

// Error model มาตรฐาน
app.Use(async (ctx, next) =>
{
    try { await next(); }
    catch (Exception ex)
    {
        ctx.Response.ContentType = "application/json";
        ctx.Response.StatusCode = 500;
        var traceId = ctx.TraceIdentifier;
        var payload = new { code = "INTERNAL_ERROR", message = ex.Message, trace_id = traceId };
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(payload));
    }
});

// ===== Minimal endpoints =====
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })); // ใช้เป็น HTTP health check
app.MapMetrics("/metrics"); // Prometheus scrape

// Auth demo
app.MapPost("/v1/auth/login", async (LoginReq req, AppDb db) =>
{
    var u = await db.Users.SingleOrDefaultAsync(x => x.Email == req.Email);
    if (u is null || !BCrypt.Net.BCrypt.Verify(req.Password, u.PasswordHash))
        return Results.Unauthorized();

    var token = Jwt.Issue(jwtSecret, u.Id.ToString(), new[] { "user" }, TimeSpan.FromMinutes(15));
    var refresh = Jwt.Issue(jwtSecret, u.Id.ToString(), new[] { "refresh" }, TimeSpan.FromDays(30));
    return Results.Ok(new { access_token = token, refresh_token = refresh });
});

app.MapGet("/v1/users/me", (ClaimsPrincipal user) =>
{
    if (!user.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    return Results.Ok(new { sub = user.FindFirstValue(ClaimTypes.NameIdentifier) });
}).RequireAuthorization().RequireRateLimiting("fixed");

app.Run();

// ===== EF Core =====
public class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
}
public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = default!;
    public string PasswordHash { get; set; } = default!;
}

// ===== DTO =====
public record LoginReq(string Email, string Password);

// ===== JWT helper =====
static class Jwt
{
    public static string Issue(string secret, string sub, IEnumerable<string> scopes, TimeSpan ttl)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var now = DateTime.UtcNow;
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, sub) };
        claims.AddRange(scopes.Select(s => new Claim("scope", s)));
        var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: claims, notBefore: now, expires: now.Add(ttl), signingCredentials: creds);
        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
