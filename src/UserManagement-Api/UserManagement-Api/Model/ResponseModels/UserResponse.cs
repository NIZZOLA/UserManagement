using Microsoft.AspNetCore.Identity;

namespace UserManagement_Api.Model.ResponseModels;

public class UserResponse
{
    public UserResponse(IdentityUser user)
    {
        this.Id = user.Id;
        this.Email = user.Email;
        this.UserName = user.UserName;
    }
    public string Id { get; set; }
    public string UserName { get; set; }
    public string Email { get; set; }
    //public IList<string> Roles { get; set; } = new List<string>();
}
