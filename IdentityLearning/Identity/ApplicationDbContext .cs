namespace IdentityLearning.Identity
{
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;

    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users => Set<User>();

        public DbSet<Role> Roles => Set<Role>();

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) :
            base(options)
        {
            Database.EnsureCreated();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var adminRole = new Role { Id = "e1110812-5f76-4889-93a7-b4c677c2d8dd", Name = "Admin" };
            var userRole = new Role { Id = "beea0094-0cde-4f04-812b-98c02f4f8e27", Name = "User" };

            modelBuilder.Entity<Role>().HasKey(r => r.Id);
            modelBuilder.Entity<Role>().HasMany(r => r.Users);
            modelBuilder.Entity<Role>().HasData(adminRole, userRole);

            var adminUser = new User
            {
                Id = "2288a9b4-35ee-4c13-b863-36184e701e0a",
                Name = "admin@gmail.com",
                RoleId = adminRole.Id,
            };
            var firstUser = new User
            {
                Id = "5eb5d348-b220-4148-8f9b-570de6262aa8",
                Name = "user1@gmail.com",
                RoleId = userRole.Id,
            };

            var passwordHasher = new PasswordHasher<User>();
            adminUser.PasswordHash = passwordHasher.HashPassword(adminUser, "admin-123");
            firstUser.PasswordHash = passwordHasher.HashPassword(firstUser, "123456qw");

            modelBuilder.Entity<User>().HasKey(u => u.Id);
            modelBuilder.Entity<User>().HasOne(u => u.Role);
            modelBuilder.Entity<User>().HasData(adminUser, firstUser);

            base.OnModelCreating(modelBuilder);
        }
    }
}
