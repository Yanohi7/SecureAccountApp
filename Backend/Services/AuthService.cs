using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Backend.Data;
using Backend.Models;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Backend.Services;

public class AuthService
{
    private readonly AppDbContext _context;
    private readonly EmailService _emailService;
    private readonly CaptchaService _captchaService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;
    private readonly PasswordHasher<User> _hasher = new();

    public const int MaxFailedAttempts = 5;
    public const int LockoutMinutes = 15;

    public AuthService(AppDbContext context, EmailService emailService, CaptchaService captchaService, IConfiguration configuration, ILogger<AuthService> logger)
    {
        _context = context;
        _emailService = emailService;
        _captchaService = captchaService;
        _configuration = configuration;
        _logger = logger;
    }

    public (bool IsValid, string ErrorMessage) ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return (false, "Пароль повинен містити щонайменше 8 символів.");
        if (!Regex.IsMatch(password, @"[A-Z]"))
            return (false, "Пароль повинен містити хоча б одну велику літеру.");
        if (!Regex.IsMatch(password, @"[a-z]"))
            return (false, "Пароль повинен містити хоча б одну малу літеру.");
        if (!Regex.IsMatch(password, @"[0-9]"))
            return (false, "Пароль повинен містити хоча б одну цифру.");
        if (!Regex.IsMatch(password, @"[^\p{L}\p{N}\s]"))
            return (false, "Пароль повинен містити хоча б один спеціальний символ.");

        return (true, string.Empty);
    }

    public async Task<(bool Success, string Message)> RegisterAsync(RegisterDto dto)
    {
        if (!_captchaService.Validate(dto.CaptchaId, dto.CaptchaCode))
        {
            return (false, "Невірний код перевірки з картинки (CAPTCHA) або термін його дії минув.");
        }

        var email = NormalizeEmail(dto.Email);
        if (!new EmailAddressAttribute().IsValid(email) || email.Length > 254)
            return (false, "Вкажіть коректну електронну адресу.");

        var (isValid, errorMessage) = ValidatePassword(dto.Password);
        if (!isValid)
            return (false, errorMessage);

        await using var transaction = await _context.Database.BeginTransactionAsync();
        if (await _context.Users.AnyAsync(u => u.Email.ToLower() == email))
            return (false, "Користувач із такою електронною поштою вже існує.");

        var isFirstUser = !await _context.Users.AnyAsync();
        var activationToken = GenerateToken();

        var newUser = new User
        {
            Email = email,
            Role = isFirstUser ? "Admin" : "User",
            ActivationToken = activationToken,
            TokenExpiresAt = DateTime.UtcNow.AddHours(24)
        };

        newUser.PasswordHash = _hasher.HashPassword(newUser, dto.Password);

        _context.Users.Add(newUser);
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        try
        {
            await _emailService.SendActivationEmailAsync(newUser.Email, activationToken);
        }
        catch (Exception)
        {
            return (true, "Акаунт створено. Якщо лист не надійшов, увійдіть і надішліть його повторно з профілю.");
        }

        return (true, "Реєстрація успішна! Будь ласка, перевірте пошту для активації акаунта.");
    }

    public async Task<(bool Success, string Message, User? User, string? Challenge)> LoginAsync(
        LoginDto dto, string? ipAddress)
    {
        var email = NormalizeEmail(dto.Email);
        await using var transaction = await _context.Database.BeginTransactionAsync();
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email.ToLower() == email);

        if (user == null)
        {
            RecordLoginLog(email, ipAddress, false, "Користувача не знайдено");
            await transaction.CommitAsync();
            return (false, "Невірний email або пароль.", null, null);
        }

        if (LoginRestriction(user) is { } restriction)
        {
            RecordLoginLog(user.Email, ipAddress, false, restriction);
            await transaction.CommitAsync();
            return (false, restriction, null, null);
        }

        var verification = _hasher.VerifyHashedPassword(user, user.PasswordHash, dto.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            if (user.LockoutEnd.HasValue)
                user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            user.FailedLoginAttempts++;
            if (user.FailedLoginAttempts >= MaxFailedAttempts)
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutMinutes);

            await _context.SaveChangesAsync();
            var message = user.LockoutEnd.HasValue
                ? $"Перевищено ліміт невдалих спроб. Акаунт заблоковано на {LockoutMinutes} хв."
                : $"Невірний email або пароль. Залишилось спроб: {MaxFailedAttempts - user.FailedLoginAttempts}.";
            RecordLoginLog(user.Email, ipAddress, false, message);
            await transaction.CommitAsync();
            return (false, message, null, null);
        }

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            user.PasswordHash = _hasher.HashPassword(user, dto.Password);
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return await CompleteFirstFactorAsync(user, ipAddress, "Успішний вхід");
    }

    public async Task<(bool Success, string Message, User? User, string? Challenge)> GoogleLoginAsync(
        string idToken, string? ipAddress)
    {
        var clientId = _configuration["GoogleAuth:ClientId"];
        if (string.IsNullOrWhiteSpace(clientId))
            return (false, "Вхід через Google не налаштовано.", null, null);

        GoogleJsonWebSignature.Payload payload;
        try
        {
            payload = await GoogleJsonWebSignature.ValidateAsync(idToken,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [clientId] });
        }
        catch (InvalidJwtException)
        {
            RecordLoginLog("Google", ipAddress, false, "Недійсний ID-токен Google");
            return (false, "Не вдалося перевірити обліковий запис Google.", null, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Google ID token verification failed.");
            return (false, "Не вдалося з’єднатися із сервісом Google.", null, null);
        }

        if (!payload.EmailVerified || string.IsNullOrWhiteSpace(payload.Email) || string.IsNullOrWhiteSpace(payload.Subject))
            return (false, "Google не підтвердив особу або електронну пошту.", null, null);

        var email = NormalizeEmail(payload.Email);
        var googleManagesEmail = email.EndsWith("@gmail.com", StringComparison.Ordinal) ||
            !string.IsNullOrWhiteSpace(payload.HostedDomain);

        await using var transaction = await _context.Database.BeginTransactionAsync();
        var user = await _context.Users.SingleOrDefaultAsync(u => u.GoogleSubject == payload.Subject);
        if (user == null)
        {
            user = await _context.Users.SingleOrDefaultAsync(u => u.Email.ToLower() == email);
            if (!googleManagesEmail)
                return (false, "Увійдіть через Google із підтвердженою адресою Gmail або Google Workspace.", null, null);

            if (user == null)
            {
                var isFirstUser = !await _context.Users.AnyAsync();
                user = new User { Email = email, Role = isFirstUser ? "Admin" : "User" };
                _context.Users.Add(user);
            }
            else if (!user.IsActive || user.GoogleSubject != null)
            {
                return (false, "Цей Google-акаунт не прив’язано до наявного профілю.", null, null);
            }
        }

        if (LoginRestriction(user) is { } restriction)
        {
            RecordLoginLog(user.Email, ipAddress, false, restriction);
            await transaction.CommitAsync();
            return (false, restriction, null, null);
        }

        user.GoogleSubject = payload.Subject;
        user.IsActive = true;
        user.ActivationToken = null;
        user.TokenExpiresAt = null;
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return await CompleteFirstFactorAsync(user, ipAddress, "Успішний вхід через Google");
    }

    private async Task<(bool Success, string Message, User? User, string? Challenge)> CompleteFirstFactorAsync(
        User user, string? ipAddress, string successMessage)
    {
        if (!user.TwoFactorEnabled)
        {
            RecordLoginLog(user.Email, ipAddress, true, successMessage);
            return (true, successMessage, user, null);
        }

        var challenge = GenerateToken();
        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        var changed = await _context.Users.Where(u => u.Id == user.Id && !u.IsBlocked &&
                u.TwoFactorEnabled && u.SessionVersion == user.SessionVersion &&
                (u.LockoutEnd == null || u.LockoutEnd <= DateTime.UtcNow))
            .ExecuteUpdateAsync(update => update
                .SetProperty(u => u.TwoFactorChallenge, challenge)
                .SetProperty(u => u.TwoFactorCode, code)
                .SetProperty(u => u.TwoFactorCodeExpiresAt, DateTime.UtcNow.AddMinutes(5))
                .SetProperty(u => u.TwoFactorAttempts, 0));
        if (changed == 0)
            return (false, "Стан акаунта змінився. Увійдіть знову.", null, null);

        try
        {
            await _emailService.SendTwoFactorCodeEmailAsync(user.Email, code);
            return (true, "На вашу пошту надіслано шестизначний код підтвердження.", user, challenge);
        }
        catch
        {
            await _context.Users.Where(u => u.Id == user.Id && u.TwoFactorChallenge == challenge)
                .ExecuteUpdateAsync(update => update.SetProperty(u => u.TwoFactorChallenge, (string?)null)
                    .SetProperty(u => u.TwoFactorCode, (string?)null)
                    .SetProperty(u => u.TwoFactorCodeExpiresAt, (DateTime?)null));
            RecordLoginLog(user.Email, ipAddress, false, "Не вдалося надіслати код 2FA");
            return (false, "Не вдалося надіслати код 2FA. Перевірте налаштування SMTP.", null, null);
        }
    }

    public async Task<(bool Success, string Message, User? User)> VerifyTwoFactorAsync(
        VerifyTwoFactorDto dto, string? ipAddress)
    {
        const string invalid = "Код невірний або прострочений. Після п’яти помилок увійдіть знову.";
        if (dto.Challenge.Length != 64)
            return (false, invalid, null);

        await using var transaction = await _context.Database.BeginTransactionAsync();
        var user = await _context.Users.SingleOrDefaultAsync(u => u.TwoFactorChallenge == dto.Challenge);
        if (user == null || !user.TwoFactorEnabled || LoginRestriction(user) != null ||
            user.TwoFactorCodeExpiresAt is not { } expiresAt || expiresAt <= DateTime.UtcNow)
            return (false, invalid, null);

        if (user.TwoFactorCode != dto.Code.Trim())
        {
            user.TwoFactorAttempts++;
            if (user.TwoFactorAttempts >= MaxFailedAttempts)
                ClearTwoFactorChallenge(user);
            await _context.SaveChangesAsync();
            RecordLoginLog(user.Email, ipAddress, false, "Невірний код 2FA");
            await transaction.CommitAsync();
            return (false, invalid, null);
        }

        ClearTwoFactorChallenge(user);
        await _context.SaveChangesAsync();
        RecordLoginLog(user.Email, ipAddress, true, "Успішний вхід із 2FA");
        await transaction.CommitAsync();
        return (true, "Двоетапну перевірку пройдено успішно!", user);
    }

    public async Task<(bool Success, string Message)> ToggleTwoFactorAsync(Guid userId, bool enable)
    {
        var user = await GetUserAsync(userId);
        if (user == null || !user.IsActive)
            return (false, "Спочатку активуйте обліковий запис.");

        user.TwoFactorEnabled = enable;
        ClearTwoFactorChallenge(user);
        await _context.SaveChangesAsync();

        return (true, enable
            ? "Двофакторну автентифікацію увімкнено."
            : "Двофакторну автентифікацію вимкнено.");
    }

    public Task<User?> GetUserAsync(Guid userId) => _context.Users.SingleOrDefaultAsync(u => u.Id == userId);

    public Task<int> EndSessionAsync(Guid userId) => _context.Users.Where(u => u.Id == userId)
        .ExecuteUpdateAsync(update => update.SetProperty(u => u.SessionVersion, u => u.SessionVersion + 1));

    public async Task<(bool Success, string Message)> ResendActivationEmailAsync(Guid userId)
    {
        var user = await GetUserAsync(userId);
        if (user == null)
            return (false, "Користувача не знайдено.");

        if (user.IsActive)
            return (false, "Обліковий запис уже активовано.");

        var activationToken = GenerateToken();
        user.ActivationToken = activationToken;
        user.TokenExpiresAt = DateTime.UtcNow.AddHours(24);
        await _context.SaveChangesAsync();

        try
        {
            await _emailService.SendActivationEmailAsync(user.Email, activationToken);
            return (true, "Новий лист активації надіслано на вашу пошту.");
        }
        catch
        {
            return (false, "Помилка надсилання листа. Перевірте налаштування пошти.");
        }
    }

    private static string? LoginRestriction(User user)
    {
        if (user.IsBlocked)
            return "Ваш обліковий запис заблоковано адміністратором.";
        if (user.LockoutEnd is { } lockedUntil && lockedUntil > DateTime.UtcNow)
            return $"Обліковий запис тимчасово заблоковано. Спробуйте знову після {lockedUntil:HH:mm} UTC.";
        return null;
    }

    private static void ClearTwoFactorChallenge(User user)
    {
        user.TwoFactorChallenge = null;
        user.TwoFactorCode = null;
        user.TwoFactorCodeExpiresAt = null;
        user.TwoFactorAttempts = 0;
    }

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static string GenerateToken() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    public (bool Success, string Message) ActivateAccount(string token)
    {
        using var transaction = _context.Database.BeginTransaction();
        var user = _context.Users.SingleOrDefault(u => u.ActivationToken == token);
        if (user == null)
            return (false, "Недійсний токен активації.");

        if (user.TokenExpiresAt is not { } expiresAt || expiresAt <= DateTime.UtcNow)
            return (false, "Термін дії токена активації минув.");

        user.IsActive = true;
        user.ActivationToken = null;
        user.TokenExpiresAt = null;
        _context.SaveChanges();
        transaction.Commit();

        return (true, "Обліковий запис успішно активовано! Тепер ви маєте повний доступ.");
    }

    public async Task<(bool Success, string Message)> ForgotPasswordAsync(string email)
    {
        const string response = "Якщо акаунт існує, на його пошту буде надіслано посилання для відновлення.";
        var normalizedEmail = NormalizeEmail(email);
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Email.ToLower() == normalizedEmail);
        if (user == null)
            return (true, response);

        var resetToken = GenerateToken();

        user.ResetToken = resetToken;
        user.ResetTokenExpiresAt = DateTime.UtcNow.AddHours(1);
        await _context.SaveChangesAsync();

        try
        {
            await _emailService.SendPasswordResetEmailAsync(user.Email, resetToken);
            return (true, response);
        }
        catch (Exception)
        {
            return (true, response);
        }
    }

    public async Task<(bool Success, string Message)> ResetPasswordAsync(ResetPasswordDto dto)
    {
        var (isValid, errorMessage) = ValidatePassword(dto.NewPassword);
        if (!isValid)
            return (false, errorMessage);

        await using var transaction = await _context.Database.BeginTransactionAsync();
        var user = await _context.Users.SingleOrDefaultAsync(u => u.ResetToken == dto.Token);
        if (user == null)
            return (false, "Недійсний токен скидання пароля.");

        if (user.ResetTokenExpiresAt is not { } expiresAt || expiresAt <= DateTime.UtcNow)
            return (false, "Термін дії токена відновлення минув. Замовте новий лист.");

        user.PasswordHash = _hasher.HashPassword(user, dto.NewPassword);
        user.ResetToken = null;
        user.ResetTokenExpiresAt = null;
        user.SessionVersion++;
        ClearTwoFactorChallenge(user);
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return (true, "Пароль успішно змінено! Тепер ви можете увійти з новим паролем.");
    }

    private void RecordLoginLog(string email, string? ipAddress, bool isSuccess, string details)
    {
        _context.LoginAuditLogs.Add(new LoginAuditLog
        {
            Email = email,
            IpAddress = ipAddress,
            Timestamp = DateTime.UtcNow,
            IsSuccess = isSuccess,
            Details = details
        });
        _context.SaveChanges();
    }
}
