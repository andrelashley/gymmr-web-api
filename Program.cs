using GymmrWebApi.Data;
using GymmrWebApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentity<AppUser, IdentityRole>(cfg =>
{
    cfg.User.RequireUniqueEmail = true;
    cfg.Password.RequireUppercase = false;
    cfg.Password.RequireDigit = false;
    cfg.Password.RequireNonAlphanumeric = false;
}).AddEntityFrameworkStores<DataContext>();

// Add services to the container.
builder.Services.AddDbContext<DataContext>(x => x.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddControllers();

builder.Services.AddHealthChecks();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<DataContext>();
    await context.Database.MigrateAsync();
}

// Configure the HTTP request pipeline.

app.MapHealthChecks("/hc");

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
