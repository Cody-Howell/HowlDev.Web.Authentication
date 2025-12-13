namespace HowlDev.Web.Authentication.AccountAuth.Interfaces;

public interface IAuthService {
    Task<Account> GetUserAsync(string account);
    Task<IEnumerable<Account>> QueryUsersAsync(string query, int limit);
    Task<IEnumerable<Account>> QueryUsersAboveRoleAsync(int role, int limit);
    Task<IEnumerable<Account>> QueryUsersAboveOrAtRoleAsync(int role, int limit);
    Task<IEnumerable<Account>> QueryUsersAtRoleAsync(int role, int limit);
    Task<IEnumerable<Account>> QueryUsersBelowOrAtRoleAsync(int role, int limit);
    Task<IEnumerable<Account>> QueryUsersBelowRoleAsync(int role, int limit);
    Task<IEnumerable<Account>> GetAllUsersAsync();
    Task AddUserAsync(string accountName, string defaultPassword, int defaultRole);
    Task DeleteUserAsync(string accountId);
    Task ExpiredKeySignOutAsync(TimeSpan length);
    Task<int> GetCurrentSessionCountAsync(string account);
    Task<Guid> GetGuidAsync(string account);
    Task<string> GetAccountNameAsync(Guid account);
    Task<int> GetRoleAsync(string account);
    Task<DateTime> IsValidApiKeyAsync(string accountName, string key);
    Task<bool> IsValidUserPassAsync(string accountName, string password);
    Task GlobalSignOutAsync(string accountId);
    Task KeySignOutAsync(string accountId, string key);
    Task<string> NewSignInAsync(string accountName);
    Task ReValidateAsync(string accountId, string key);
    Task UpdatePasswordAsync(string accountName, string newPassword);
    Task UpdateRoleAsync(string accountName, int newRole);
}
