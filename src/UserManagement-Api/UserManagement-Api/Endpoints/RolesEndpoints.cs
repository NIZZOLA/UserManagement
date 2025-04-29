using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace UserManagement_Api.Endpoints
{
    public static class RolesEndpoints
    {
        public static void MapRoleEndpoints(this IEndpointRouteBuilder routes)
        {
            var group = routes.MapGroup("/api/role").WithTags("Roles");

            group.MapPost("/create", async ([FromServices] RoleManager<IdentityRole> roleManager,
                [FromBody] string roleName) =>
            {
                if (string.IsNullOrEmpty(roleName))
                    return Results.BadRequest("Nome da role não pode ser vazio.");

                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (roleExists)
                    return Results.Conflict($"Role '{roleName}' já existe.");

                var result = await roleManager.CreateAsync(new IdentityRole(roleName));
                return result.Succeeded
                    ? Results.Ok($"Role '{roleName}' criada com sucesso.")
                    : Results.BadRequest(result.Errors);
            }).RequireAuthorization(); // Protege o endpoint (só admin pode criar roles)

            group.MapGet("/list", async ([FromServices] RoleManager<IdentityRole> roleManager) =>
            {
                var roles = await roleManager.Roles.ToListAsync();
                return Results.Ok(roles.Select(r => r.Name));
            }).RequireAuthorization(); // Protege o endpoint (opcional)
        }
    }
}
