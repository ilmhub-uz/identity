using System.Reflection;
using identity.CustomValidators;
using identity.Data;
using identity.Entity;
using identity.Services;
using IdentityServer4;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SendGrid.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContextPool<ApplicationDbContext>(
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("IdentityConnection")));

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
    options.TokenLifespan = TimeSpan.FromDays(1));

builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;

    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false;
})
.AddErrorDescriber<UserValidationErrorDescriber>()
.AddUserValidator<UserValidator>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

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

        options.ClientId = builder.Configuration["ExternalProviders:Google:ClientId"];
        options.ClientSecret = builder.Configuration["ExternalProviders:Google:ClientSecret"];
    })
    .AddGitHub("Github", options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

        options.ClientId =builder.Configuration["ExternalProviders:Github:ClientId"];
        options.ClientSecret =  builder.Configuration["ExternalProviders:Github:ClientSecret"];

        options.Scope.Add("user:email");
    });

builder.Services.AddSingleton<MessageQueue<KeyValuePair<Guid, identity.EmailModels.Models.Message>>>();
builder.Services.AddSendGrid(options => options.ApiKey = builder.Configuration["SendGrid:ApiKey"]);
builder.Services.AddHostedService<MessageQueueService>();
builder.Services.AddScoped<UserValidationErrorDescriber>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseStaticFiles();
app.UseCors();

app.UseIdentityServer();
app.UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = SameSiteMode.Lax });

app.UseAuthentication();
app.UseAuthorization();

app.MapDefaultControllerRoute();

Seed.MigrateDatabases(app);

Seed.InitializeConfiguration(app).GetAwaiter().GetResult();
Seed.InitializeTestUsers(app).GetAwaiter().GetResult();

app.Run();