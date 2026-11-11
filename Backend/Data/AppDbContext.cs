using Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace Backend.Data;

public class AppDbContext : DbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<LoginAuditLog> LoginAuditLogs => Set<LoginAuditLog>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }
}
