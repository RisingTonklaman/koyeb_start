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
var dbUrl = DbUrl.NormalizeDbUrl(rawDbUrl);
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
    // Add JWT Bearer auth to Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter 'Bearer <token>'"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ===== CORS =====
builder.Services.AddCors(p => p.AddDefaultPolicy(policy =>
    policy.WithOrigins(allowOrigin == "*" ? Array.Empty<string>() : new[] { allowOrigin })
          .AllowAnyHeader()
          .AllowAnyMethod()
          .SetIsOriginAllowed(_ => allowOrigin == "*")));

// ===== Health checks & Metrics =====
// Health check registered once above with DB; only map metrics here.

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

// Redirect root to Swagger UI for convenience
app.MapGet("/", () => Results.Redirect("/swagger"));

// Auth demo
app.MapPost("/v1/auth/login", async (LoginReq req, AppDb db) =>
{
    var u = await db.Users.SingleOrDefaultAsync(x => x.Email == req.Email);
    if (u is null || !BCrypt.Net.BCrypt.Verify(req.Password, u.PasswordHash))
        return Results.Unauthorized();

    var token = JwtHelper.Issue(jwtSecret, u.Id.ToString(), new[] { "user" }, TimeSpan.FromMinutes(15));
    var refresh = JwtHelper.Issue(jwtSecret, u.Id.ToString(), new[] { "refresh" }, TimeSpan.FromDays(30));
    return Results.Ok(new { access_token = token, refresh_token = refresh });
});

// Register
app.MapPost("/v1/auth/register", async (RegisterReq req, AppDb db) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { code = "INVALID_INPUT", message = "email and password are required" });

    var exists = await db.Users.AnyAsync(u => u.Email == req.Email);
    if (exists) return Results.Conflict(new { code = "EMAIL_TAKEN", message = "Email already registered" });

    var user = new User { Email = req.Email, PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password) };
    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Created($"/v1/users/{user.Id}", new { id = user.Id, email = user.Email });
});

app.MapGet("/v1/users/me", (ClaimsPrincipal user) =>
{
    if (!user.Identity?.IsAuthenticated ?? true) return Results.Unauthorized();
    return Results.Ok(new { sub = user.FindFirstValue(ClaimTypes.NameIdentifier) });
}).RequireAuthorization().RequireRateLimiting("fixed");

app.Run();
