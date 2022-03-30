using identity.Entity;
using ilmhub.entity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace identity.Data;

public class ApplicationDbContext : IdentityDbContext<User>
{
    public DbSet<Message> Messages { get; set; }
    
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
}