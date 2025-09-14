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
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ===== Config & Secrets =====
var rawDbUrl = Environment.GetEnvironmentVariable("DATABASE_URL")
               ?? builder.Configuration.GetConnectionString("Default");
var dbUrl = NormalizeDbUrl(rawDbUrl);
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
builder.Services.AddHealthChecks().AddNpgSql(dbUrl, name: "postgres");

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
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "API", Version = "v1" });
});

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

// Convert postgres style DATABASE_URL to an Npgsql connection string if needed
static string NormalizeDbUrl(string? input)
{
    if (string.IsNullOrWhiteSpace(input)) return input ?? string.Empty;
    // Already looks like key=value;
    if (input.Contains('=') && input.Contains(';')) return input; // assume already proper
    // Expect formats like: postgres://user:pass@host:5432/dbname or postgresql://
    if (input.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) ||
        input.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
    {
        // Use Uri to parse
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri)) return input; // fallback
        var userInfo = uri.UserInfo.Split(':');
        var username = Uri.UnescapeDataString(userInfo.ElementAtOrDefault(0) ?? "");
        var password = Uri.UnescapeDataString(userInfo.ElementAtOrDefault(1) ?? "");
        var host = uri.Host;
        var port = uri.IsDefaultPort ? 5432 : uri.Port;
        var database = uri.AbsolutePath.TrimStart('/');
        // Optional query parameters (sslmode, etc.)
        var builder = new StringBuilder();
        void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) builder.Append(k).Append('=').Append(v).Append(';'); }
        Add("Host", host);
        Add("Port", port.ToString());
        Add("Username", username);
        Add("Password", password);
        Add("Database", database);
        // Parse query parameters
        var q = uri.Query;
        if (!string.IsNullOrEmpty(q))
        {
            var query = System.Web.HttpUtility.ParseQueryString(q);
            foreach (var key in query.AllKeys!)
            {
                var val = query[key];
                if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(val))
                    Add(key!, val!);
            }
        }
        return builder.ToString();
    }
    return input; // unknown format, just return
}
