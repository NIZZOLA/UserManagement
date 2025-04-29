namespace UserManagement_Api.Model;

public class AssignClaimToRoleRequest
{
    public required string RoleName { get; set; }
    public required string ClaimType { get; set; }
    public required string ClaimValue { get; set; }
}
