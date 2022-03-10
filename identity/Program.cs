using System.Reflection;
using identity.Data;
using identity.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContextPool<ApplicationDbContext>(
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("IdentityConnection")));

builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;

    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>();

var migrationsAssembly = typeof(Program).GetTypeInfo().Assembly.GetName().Name;

builder.Services.AddIdentityServer()
.AddAspNetIdentity<User>()
.AddConfigurationStore(options =>
{
    options.ConfigureDbContext = b
        => b.UseSqlServer(builder.Configuration.GetConnectionString("IdentityConnection"), sql 
            => sql.MigrationsAssembly(migrationsAssembly));
})
.AddOperationalStore(options =>
{
    options.ConfigureDbContext = b
        => b.UseSqlServer(builder.Configuration.GetConnectionString("IdentityConnection"), sql 
            => sql.MigrationsAssembly(migrationsAssembly));
})
.AddDeveloperSigningCredential();

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseIdentityServer();

app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute();

Seed.InitializeConfiguration(app).GetAwaiter().GetResult();
Seed.InitializeTestUsers(app).GetAwaiter().GetResult();

app.Run();