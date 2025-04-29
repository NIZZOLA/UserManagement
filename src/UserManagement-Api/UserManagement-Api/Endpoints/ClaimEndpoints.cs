using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using UserManagement_Api.Model;

namespace UserManagement_Api.Endpoints;

public static class ClaimEndpoints
{
    public static void MapClaimEndpoints(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/api/claim").WithTags("Claims");

        group.MapPost("/users/assign-claim", async ([FromServices] UserManager<IdentityUser> userManager,
                [FromBody] AssignClaimToUserRequest request) =>
        {
            var user = await userManager.FindByIdAsync(request.UserId);
            if (user == null)
                return Results.NotFound("Usuário não encontrado.");

            var claim = new Claim(request.ClaimType, request.ClaimValue);
            var result = await userManager.AddClaimAsync(user, claim);

            return result.Succeeded
                ? Results.Ok("Claim adicionada ao usuário com sucesso.")
                : Results.BadRequest(result.Errors);
        }).RequireAuthorization();

        group.MapPost("/roles/assign-claim", async ([FromServices] RoleManager<IdentityRole> roleManager,
            [FromBody] AssignClaimToRoleRequest request) =>
        {
            var role = await roleManager.FindByNameAsync(request.RoleName);
            if (role == null)
                return Results.NotFound("Role não encontrada.");

            var claim = new Claim(request.ClaimType, request.ClaimValue);
            var result = await roleManager.AddClaimAsync(role, claim);

            return result.Succeeded
                ? Results.Ok("Claim adicionada à role com sucesso.")
                : Results.BadRequest(result.Errors);
        }).RequireAuthorization();

        group.MapGet("/users/{userId}/claims", async ([FromServices] UserManager<IdentityUser> userManager,
            [FromQuery] string userId) =>
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return Results.NotFound("Usuário não encontrado.");

            var claims = await userManager.GetClaimsAsync(user);
            return Results.Ok(claims.Select(c => new { c.Type, c.Value }));
        }).RequireAuthorization();

        group.MapGet("/roles/{roleName}/claims", async ([FromServices] RoleManager<IdentityRole> roleManager,
                [FromQuery] string roleName) =>
        {
            var role = await roleManager.FindByNameAsync(roleName);
            if (role == null)
                return Results.NotFound("Role não encontrada.");

            var claims = await roleManager.GetClaimsAsync(role);
            return Results.Ok(claims.Select(c => new { c.Type, c.Value }));
        }).RequireAuthorization();

        group.MapDelete("/users/remove-claim", async ([FromServices] UserManager<IdentityUser> userManager,
                [FromBody] AssignClaimToUserRequest request) =>
        {
            var user = await userManager.FindByIdAsync(request.UserId);
            if (user == null)
                return Results.NotFound("Usuário não encontrado.");

            var claim = new Claim(request.ClaimType, request.ClaimValue);
            var result = await userManager.RemoveClaimAsync(user, claim);

            return result.Succeeded
                ? Results.Ok("Claim removida do usuário com sucesso.")
                : Results.BadRequest(result.Errors);
        }).RequireAuthorization();
    }
}
