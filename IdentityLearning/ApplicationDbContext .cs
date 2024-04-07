namespace IdentityLearning
{
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;

    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) :
            base(options)
        {
            Database.EnsureCreated();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            var adminId = "2288a9b4-35ee-4c13-b863-36184e701e0a";
            var firstUserId = "5eb5d348-b220-4148-8f9b-570de6262aa8";

            var adminUser = new IdentityUser
            {
                Id = adminId,
                UserName = "admin@gmail.com",
                NormalizedUserName = "admin@gmail.com".ToUpper(),
                Email = "admin@gmail.com",
                NormalizedEmail = "admin@gmail.com".ToUpper(),
            };
            var firstUser = new IdentityUser
            {
                Id = firstUserId,
                UserName = "user1@gmail.com",
                NormalizedUserName = "user1@gmail.com".ToUpper(),
                Email = "user1@gmail.com",
                NormalizedEmail = "user1@gmail.com".ToUpper()
            };

            var passwordHasher = new PasswordHasher<IdentityUser>();
            adminUser.PasswordHash = passwordHasher.HashPassword(adminUser, "admin-123");
            firstUser.PasswordHash = passwordHasher.HashPassword(firstUser, "123456qw");

            modelBuilder.Entity<IdentityUser>().HasData(adminUser, firstUser);

            var adminRoleId = "e1110812-5f76-4889-93a7-b4c677c2d8dd";
            var userRoleId = "beea0094-0cde-4f04-812b-98c02f4f8e27";
            var adminRole = "Admin";
            var userRole = "User";
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole { Id = adminRoleId, Name = adminRole, NormalizedName = adminRole.ToUpper() },
                new IdentityRole { Id = userRoleId, Name = userRole, NormalizedName = userRole.ToUpper() }
            );

            modelBuilder.Entity<IdentityUserRole<string>>().HasData(
                new IdentityUserRole<string> { RoleId = adminRoleId, UserId = adminId },
                new IdentityUserRole<string> { RoleId = userRoleId, UserId = firstUserId }
            );
        }
    }
}
