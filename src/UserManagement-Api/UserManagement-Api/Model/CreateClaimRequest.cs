namespace UserManagement_Api.Model
{
    public class CreateClaimRequest
    {
        public required string Type { get; set; }  // Ex: "Permission", "Department"
        public required string Value { get; set; } // Ex: "Read", "Finance"
    }

}
