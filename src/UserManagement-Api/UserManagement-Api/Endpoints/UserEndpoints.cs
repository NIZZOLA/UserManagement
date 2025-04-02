using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserManagement_Api.Model;
namespace UserManagement_Api.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/user").WithTags("User");

        group.MapPost("/register", async (RegisterModel model, UserManager<IdentityUser> userManager) =>
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await userManager.CreateAsync(user, model.Password);

            return result.Succeeded
                ? Results.Ok(new { Message = "Usuário registrado com sucesso!" })
                : Results.BadRequest(result.Errors);
        });

        group.MapPost("/login", async (LoginModel model, UserManager<IdentityUser> userManager, IConfiguration config) =>
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null || !await userManager.CheckPasswordAsync(user, model.Password))
                return Results.Unauthorized();

            // Obtém as roles do usuário
            var userRoles = await userManager.GetRolesAsync(user);

            // Cria as claims (incluindo roles)
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            // Adiciona as roles como claims
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }


            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        });

        group.MapGet("/users", async (UserManager<IdentityUser> userManager) =>
        {
            var users = await userManager.Users.ToListAsync();
            return Results.Ok(users);
        });

        group.MapGet("/users/{id}", async (string id, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            return user != null ? Results.Ok(user) : Results.NotFound();
        });

        group.MapPut("/users/{id}", async (string id, UpdateUserModel model, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            user.Email = model.Email;
            user.UserName = model.Username;

            var result = await userManager.UpdateAsync(user);
            return result.Succeeded ? Results.Ok(user) : Results.BadRequest(result.Errors);
        });

        group.MapDelete("/users/{id}", async (string id, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            var result = await userManager.DeleteAsync(user);
            return result.Succeeded
                ? Results.Ok(new { Message = "Usuário deletado com sucesso." })
                : Results.BadRequest(result.Errors);
        });

        group.MapPost("/users/{id}/roles", async (string id, string roleName, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            var result = await userManager.AddToRoleAsync(user, roleName);
            return result.Succeeded
                ? Results.Ok(new { Message = $"Role '{roleName}' adicionada ao usuário." })
                : Results.BadRequest(result.Errors);
        });

        group.MapGet("/users/{id}/roles", async (string id, UserManager<IdentityUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            var roles = await userManager.GetRolesAsync(user);
            return Results.Ok(roles);
        });

    }
}
