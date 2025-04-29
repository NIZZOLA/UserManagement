using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Elfie.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserManagement_Api.Model;
using UserManagement_Api.Model.ResponseModels;

namespace UserManagement_Api.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/user").WithTags("User");

        group.MapPost("/register", async ([FromServices] UserManager<IdentityUser> userManager, [FromBody] RegisterModel model) =>
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await userManager.CreateAsync(user, model.Password);

            return result.Succeeded
                ? Results.Ok(new { Message = "Usuário registrado com sucesso!" })
                : Results.BadRequest(result.Errors);
        });

        group.MapPost("/login", async ([FromServices] UserManager<IdentityUser> userManager,
                                [FromServices] IConfiguration config, LoginModel model) =>
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

        group.MapGet("/users", async ([FromServices] UserManager<IdentityUser> userManager) =>
        {
            var users = await userManager.Users.ToListAsync();

            List<UserResponse> userList = MapUserListResponse(users);

            return Results.Ok(userList);
        });

        group.MapGet("/users/{id}", async ([FromServices] UserManager<IdentityUser> userManager, [FromQuery] string id) =>
        {
            var user = await userManager.FindByIdAsync(id);
            return user != null ? Results.Ok(user) : Results.NotFound();
        });

        group.MapPut("/users/{id}", async ([FromServices] UserManager<IdentityUser> userManager, 
                    [FromQuery] string id, [FromBody] UpdateUserModel model) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            user.Email = model.Email;
            user.UserName = model.Username;

            var result = await userManager.UpdateAsync(user);
            return result.Succeeded ? Results.Ok(user) : Results.BadRequest(result.Errors);
        });

        group.MapDelete("/users/{id}", async ([FromServices] UserManager<IdentityUser> userManager, 
                    [FromQuery] string id) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            var result = await userManager.DeleteAsync(user);
            return result.Succeeded
                ? Results.Ok(new { Message = "Usuário deletado com sucesso." })
                : Results.BadRequest(result.Errors);
        });

        //associa um usuário à um papel - (role)
        group.MapPost("/users/{id}/roles", async ([FromServices] UserManager<IdentityUser> userManager,
            [FromQuery] string id, [FromBody] string roleName) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();  

            var result = await userManager.AddToRoleAsync(user, roleName);
            return result.Succeeded
                ? Results.Ok(new { Message = $"Role '{roleName}' adicionada ao usuário." })
                : Results.BadRequest(result.Errors);
        });

        group.MapGet("/users/{id}/roles", async ([FromServices] UserManager<IdentityUser> userManager,
            [FromQuery] string id) =>
        {
            var user = await userManager.FindByIdAsync(id);
            if (user == null)
                return Results.NotFound();

            var roles = await userManager.GetRolesAsync(user);
            return Results.Ok(roles);
        });
    }

    private static List<UserResponse> MapUserListResponse(List<IdentityUser> users)
    {
        var userList = new List<UserResponse>();
        foreach (var item in users)
        {
            userList.Add(new UserResponse(item));
        }

        return userList;
    }
}
