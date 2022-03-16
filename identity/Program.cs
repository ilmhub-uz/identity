using System.Net;
using System.Reflection;
using identity.Data;
using identity.Entity;
using IdentityServer4;
using IdentityServer4.Services;
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

builder.Services.AddCors(options 
    => options.AddDefaultPolicy(builder => 
    {
        // TODO: (WA) - Allow only pre-defined origins and headers
        // TODO: probably load allowed origins/headers from config file
        builder.AllowAnyOrigin();
        builder.AllowAnyHeader();
    }));
builder.Services.AddAuthentication()
    .AddGoogle("Google", options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

        options.ClientId = builder.Configuration["Google:ClientId"];
        options.ClientSecret = builder.Configuration["Google:ClientSecret"];
    })
    .AddGitHub("Github", options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

        options.ClientId = builder.Configuration["Github:ClientId"];
        options.ClientSecret = builder.Configuration["Github:ClientSecret"];

        options.Scope.Add("user:email");
    });

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();
app.UseCors();

app.UseIdentityServer();

app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute();

Seed.InitializeConfiguration(app).GetAwaiter().GetResult();
Seed.InitializeTestUsers(app).GetAwaiter().GetResult();

app.Run();