using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdentityLearning.Identity
{
    public class UserStore : IUserStore<User>, IUserPasswordStore<User>
    {
        private readonly ApplicationDbContext _context;

        public UserStore(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
        {
            await _context.Users.AddAsync(user, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync(cancellationToken);

            return IdentityResult.Success;
        }

        public void Dispose()
        {
        }

        public async Task<User?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            return await _context.Users.Include("Role").SingleOrDefaultAsync(u => u.Id == userId, cancellationToken);
        }

        public async Task<User?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            return await _context.Users.Include("Role").SingleOrDefaultAsync(u => u.Name.ToLower() == normalizedUserName.ToLower(), cancellationToken);
        }

        public async Task<string?> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken)
        {
            var baseUser = await _context.Users.SingleOrDefaultAsync(u => u.Id == user.Id, cancellationToken);

            return baseUser?.Name;
        }

        public async Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken)
        {
            return user.Id;
        }

        public async Task<string?> GetUserNameAsync(User user, CancellationToken cancellationToken)
        {
            return user.Name;
        }

        public async Task SetNormalizedUserNameAsync(User user, string? normalizedName, CancellationToken cancellationToken)
        {
            user.Name = normalizedName;

            await _context.SaveChangesAsync();
        }

        public async Task SetUserNameAsync(User user, string? userName, CancellationToken cancellationToken)
        {
            user.Name = userName;

            await _context.SaveChangesAsync();
        }

        public async Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
        {
            _context.Entry(user).State = EntityState.Modified;

            await _context.SaveChangesAsync();

            return IdentityResult.Success;
        }

        public async Task<string?> GetPasswordHashAsync(User user, CancellationToken cancellationToken)
        {
            return user.PasswordHash;
        }

        public async Task<bool> HasPasswordAsync(User user, CancellationToken cancellationToken)
        {
            return !string.IsNullOrEmpty(user.PasswordHash);
        }

        public async Task SetPasswordHashAsync(User user, string? passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;

            await _context.SaveChangesAsync();
        }
    }
}
