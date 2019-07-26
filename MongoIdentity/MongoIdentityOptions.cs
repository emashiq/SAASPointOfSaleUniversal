namespace AspNetCore.Identity.Mongo
{
    public class MongoIdentityOptions
    {
        public string ConnectionString { get; set; } = "mongodb://localhost:27017/SAASPOS";

        public string UsersCollection { get; set; } = "Users";

        public string RolesCollection { get; set; } = "Roles";

        public bool UseDefaultIdentity { get; set; } = true;
    }
}