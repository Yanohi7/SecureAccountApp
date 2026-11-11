using System.ComponentModel.DataAnnotations;

namespace Backend.Models;

public class User
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    public string Role { get; set; } = "User";

    public bool IsActive { get; set; } = false;
    public string? ActivationToken { get; set; }
    public DateTime? TokenExpiresAt { get; set; }

    public bool IsBlocked { get; set; } = false;

    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }

    public bool TwoFactorEnabled { get; set; } = false;
    public string? TwoFactorCode { get; set; }
    public DateTime? TwoFactorCodeExpiresAt { get; set; }
    public string? TwoFactorChallenge { get; set; }
    public int TwoFactorAttempts { get; set; }
    public int SessionVersion { get; set; }
    public string? GoogleSubject { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public string? ResetToken { get; set; }
    public DateTime? ResetTokenExpiresAt { get; set; }
}

public class LoginAuditLog
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public bool IsSuccess { get; set; }
    public string? Details { get; set; }
}

public class RegisterDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string CaptchaId { get; set; } = string.Empty;
    public string CaptchaCode { get; set; } = string.Empty;
}

public class LoginDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ForgotPasswordDto
{
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordDto
{
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
}

public class VerifyTwoFactorDto
{
    public string Challenge { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
}

public class ToggleTwoFactorDto
{
    public bool Enable { get; set; }
}

public class GoogleLoginDto
{
    public string IdToken { get; set; } = string.Empty;
}
