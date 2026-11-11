using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Backend.Data;
using Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Backend.Controllers;

[ApiController]
[Authorize(Roles = "Admin")]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _context;

    public AdminController(AppDbContext context)
    {
        _context = context;
    }

    private Guid CurrentUserId() => Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var now = DateTime.UtcNow;
        var users = await _context.Users
            .OrderByDescending(u => u.CreatedAt)
            .Select(u => new
            {
                u.Id,
                u.Email,
                u.Role,
                u.IsActive,
                u.IsBlocked,
                u.FailedLoginAttempts,
                u.LockoutEnd,
                IsLockedOut = u.LockoutEnd.HasValue && u.LockoutEnd.Value > now,
                u.CreatedAt
            })
            .ToListAsync();

        return Ok(users);
    }

    [HttpPost("toggle-block/{id}")]
    public async Task<IActionResult> ToggleBlock(Guid id)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();
        var targetUser = await _context.Users.SingleOrDefaultAsync(u => u.Id == id);
        if (targetUser == null)
            return NotFound(new { message = "Користувача не знайдено." });

        if (targetUser.Id == CurrentUserId())
            return BadRequest(new { message = "Ви не можете заблокувати власний обліковий запис." });

        bool isCurrentlyBlocked = targetUser.IsBlocked || (targetUser.LockoutEnd.HasValue && targetUser.LockoutEnd.Value > DateTime.UtcNow);

        if (isCurrentlyBlocked)
        {
            targetUser.IsBlocked = false;
            targetUser.LockoutEnd = null;
            targetUser.FailedLoginAttempts = 0;
        }
        else
        {
            targetUser.IsBlocked = true;
            targetUser.SessionVersion++;
            targetUser.TwoFactorChallenge = null;
            targetUser.TwoFactorCode = null;
            targetUser.TwoFactorCodeExpiresAt = null;
        }

        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        var statusMessage = isCurrentlyBlocked ? "Користувача успішно розблоковано та скинуто спроби входу." : "Користувача заблоковано.";
        return Ok(new
        {
            message = statusMessage,
            user = new
            {
                targetUser.Id,
                targetUser.Email,
                targetUser.Role,
                targetUser.IsActive,
                targetUser.IsBlocked,
                targetUser.FailedLoginAttempts,
                targetUser.LockoutEnd,
                IsLockedOut = targetUser.LockoutEnd.HasValue && targetUser.LockoutEnd.Value > DateTime.UtcNow
            }
        });
    }

    [HttpPost("toggle-role/{id}")]
    public async Task<IActionResult> ToggleRole(Guid id)
    {
        await using var transaction = await _context.Database.BeginTransactionAsync();
        var targetUser = await _context.Users.SingleOrDefaultAsync(u => u.Id == id);
        if (targetUser == null)
            return NotFound(new { message = "Користувача не знайдено." });

        if (targetUser.Id == CurrentUserId())
            return BadRequest(new { message = "Ви не можете змінити власну роль." });

        targetUser.Role = targetUser.Role == "Admin" ? "User" : "Admin";
        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return Ok(new
        {
            message = $"Роль користувача {targetUser.Email} змінено на {targetUser.Role}.",
            user = new
            {
                targetUser.Id,
                targetUser.Email,
                targetUser.Role,
                targetUser.IsActive,
                targetUser.IsBlocked,
                targetUser.FailedLoginAttempts
            }
        });
    }

    [HttpGet("logs")]
    public async Task<IActionResult> GetAuditLogs()
    {
        var logs = await _context.LoginAuditLogs
            .OrderByDescending(l => l.Timestamp)
            .Take(100)
            .ToListAsync();

        return Ok(logs);
    }
}
