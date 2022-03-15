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

        options.ClientId = "857415523293-gg6iia7hqlosotcf86ipcat8aco9sv01.apps.googleusercontent.com";
        options.ClientSecret = "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";
    });
    // .AddOpenIdConnect("Github", "GitHub", options =>
    // {
    //     options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
    //     options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

    //     options.Authority = "https://accounts.google.com/";
    //     options.ClientId = "708996912208-9m4dkjb5hscn7cjrn5u0r4tbgkbj1fko.apps.googleusercontent.com";

    //     // options.CallbackPath = "/signin-google";
    //     options.Scope.Add("email");
    // });

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