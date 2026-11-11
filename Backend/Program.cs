using System.Security.Claims;
using System.Threading.RateLimiting;
using Backend.Data;
using Backend.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Accounts") ?? "Data Source=app.db"));

builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddSingleton<CaptchaService>();
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "SecureAccount.Session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.Events.OnValidatePrincipal = async context =>
        {
            var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            var user = Guid.TryParse(context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var id)
                ? await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id)
                : null;
            if (user == null || user.IsBlocked ||
                context.Principal?.FindFirstValue("session_version") != user.SessionVersion.ToString())
            {
                context.RejectPrincipal();
                await context.HttpContext.SignOutAsync();
                return;
            }

            var identity = (ClaimsIdentity)context.Principal!.Identity!;
            var role = user.IsActive ? user.Role : "User";
            if (identity.FindFirst(ClaimTypes.Role)?.Value != role)
            {
                foreach (var claim in identity.FindAll(ClaimTypes.Role).ToArray())
                    identity.RemoveClaim(claim);
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
                context.ShouldRenew = true;
            }
        };
    });

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 90,
            Window = TimeSpan.FromMinutes(1)
        }));
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReact", policy =>
    {
        policy.WithOrigins(builder.Configuration["FrontendOrigin"] ?? "http://localhost:5173")
              .AllowCredentials()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();

    try
    {
        db.Database.ExecuteSqlRaw(@"
            CREATE TABLE IF NOT EXISTS LoginAuditLogs (
                Id TEXT PRIMARY KEY,
                Email TEXT NOT NULL,
                IpAddress TEXT,
                Timestamp TEXT NOT NULL,
                IsSuccess INTEGER NOT NULL,
                Details TEXT
            );
        ");

        var connection = db.Database.GetDbConnection();
        connection.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "PRAGMA table_info(Users)";
        var existingCols = new List<string>();
        using (var reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                existingCols.Add(reader.GetString(1));
            }
        }

        if (!existingCols.Contains("IsBlocked"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN IsBlocked INTEGER NOT NULL DEFAULT 0;");
        if (!existingCols.Contains("ResetToken"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN ResetToken TEXT NULL;");
        if (!existingCols.Contains("ResetTokenExpiresAt"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN ResetTokenExpiresAt TEXT NULL;");
        if (!existingCols.Contains("TwoFactorEnabled"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN TwoFactorEnabled INTEGER NOT NULL DEFAULT 0;");
        if (!existingCols.Contains("TwoFactorCode"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN TwoFactorCode TEXT NULL;");
        if (!existingCols.Contains("TwoFactorCodeExpiresAt"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN TwoFactorCodeExpiresAt TEXT NULL;");
        if (!existingCols.Contains("FailedLoginAttempts"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN FailedLoginAttempts INTEGER NOT NULL DEFAULT 0;");
        if (!existingCols.Contains("LockoutEnd"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN LockoutEnd TEXT NULL;");
        if (!existingCols.Contains("TwoFactorChallenge"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN TwoFactorChallenge TEXT NULL;");
        if (!existingCols.Contains("TwoFactorAttempts"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN TwoFactorAttempts INTEGER NOT NULL DEFAULT 0;");
        if (!existingCols.Contains("SessionVersion"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN SessionVersion INTEGER NOT NULL DEFAULT 0;");
        if (!existingCols.Contains("GoogleSubject"))
            db.Database.ExecuteSqlRaw("ALTER TABLE Users ADD COLUMN GoogleSubject TEXT NULL;");
        db.Database.ExecuteSqlRaw("CREATE UNIQUE INDEX IF NOT EXISTS IX_Users_GoogleSubject ON Users (GoogleSubject);");
        db.Database.ExecuteSqlRaw("CREATE UNIQUE INDEX IF NOT EXISTS IX_Users_EmailNormalized ON Users (lower(Email));");
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException("Could not initialize the accounts database.", ex);
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowReact");
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api") && HttpMethods.IsPost(context.Request.Method) &&
        context.Request.Headers["X-Requested-With"] != "SecureAccountApp")
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { message = "Некоректний запит." });
        return;
    }
    await next();
});
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
