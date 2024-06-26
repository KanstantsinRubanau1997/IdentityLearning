﻿namespace IdentityLearning.Identity
{
    public class User
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string PasswordHash { get; set; }

        public string RoleId { get; set; }

        public Role Role { get; set; }
    }
}
