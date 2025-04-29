namespace UserManagement_Api.Model;

public class AssignClaimToUserRequest
{
    public required string UserId { get; set; }
    public required string ClaimType { get; set; }
    public required string ClaimValue { get; set; }
}
