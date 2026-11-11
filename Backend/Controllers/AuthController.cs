using System.Security.Claims;
using Backend.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers;

[ApiController]
[EnableRateLimiting("auth")]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;

    private readonly CaptchaService _captchaService;
    private readonly IConfiguration _configuration;

    public AuthController(AuthService authService, CaptchaService captchaService, IConfiguration configuration)
    {
        _authService = authService;
        _captchaService = captchaService;
        _configuration = configuration;
    }

    [HttpGet("captcha")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult GetCaptcha()
    {
        var (captchaId, image) = _captchaService.GenerateCaptcha();
        return Ok(new { captchaId, image });
    }

    [HttpGet("google-config")]
    public IActionResult GoogleConfig() => Ok(new { clientId = _configuration["GoogleAuth:ClientId"] });

    [Authorize]
    [HttpGet("me")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetProfile()
    {
        var user = await _authService.GetUserAsync(CurrentUserId());
        return user == null ? Unauthorized() : Ok(new { user = Profile(user) });
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _authService.EndSessionAsync(CurrentUserId());
        await HttpContext.SignOutAsync();
        return Ok(new { message = "Ви успішно вийшли з системи." });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var result = await _authService.RegisterAsync(dto);
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.LoginAsync(dto, ip);
        if (!result.Success)
            return Unauthorized(new { message = result.Message });

        return await CompleteLoginAsync(result.User!, result.Message, result.Challenge);
    }

    [HttpPost("google-login")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto dto)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.GoogleLoginAsync(dto.IdToken, ip);
        if (!result.Success)
            return Unauthorized(new { message = result.Message });

        return await CompleteLoginAsync(result.User!, result.Message, result.Challenge);
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] VerifyTwoFactorDto dto)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _authService.VerifyTwoFactorAsync(dto, ip);
        if (!result.Success)
            return Unauthorized(new { message = result.Message });

        return await CompleteLoginAsync(result.User!, result.Message);
    }

    [Authorize]
    [HttpPost("toggle-2fa")]
    public async Task<IActionResult> ToggleTwoFactor([FromBody] ToggleTwoFactorDto dto)
    {
        var result = await _authService.ToggleTwoFactorAsync(CurrentUserId(), dto.Enable);
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message, twoFactorEnabled = dto.Enable });
    }

    [Authorize]
    [HttpPost("resend-activation")]
    public async Task<IActionResult> ResendActivation()
    {
        var result = await _authService.ResendActivationEmailAsync(CurrentUserId());
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message });
    }

    [HttpGet("activate")]
    public IActionResult Activate([FromQuery] string token)
    {
        var result = _authService.ActivateAccount(token);
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
    {
        var result = await _authService.ForgotPasswordAsync(dto.Email);
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
    {
        var result = await _authService.ResetPasswordAsync(dto);
        if (!result.Success)
            return BadRequest(new { message = result.Message });

        return Ok(new { message = result.Message });
    }

    private Guid CurrentUserId() => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    private async Task<IActionResult> CompleteLoginAsync(User user, string message, string? challenge = null)
    {
        if (challenge != null)
        {
            await HttpContext.SignOutAsync();
            return Ok(new { requiresTwoFactor = true, message, user.Email, challenge });
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.IsActive ? user.Role : "User"),
                new Claim("session_version", user.SessionVersion.ToString())
            ],
            CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(new ClaimsPrincipal(identity));
        return Ok(new { message, user = Profile(user) });
    }

    private static object Profile(User user) => new
    {
        user.Id,
        user.Email,
        Role = user.IsActive ? user.Role : "User",
        user.IsActive,
        user.IsBlocked,
        user.TwoFactorEnabled,
        user.CreatedAt
    };
}
