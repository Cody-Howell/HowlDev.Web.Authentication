namespace HowlDev.Web.Authentication.AccountAuth.Interfaces;

/// <summary/>
public interface IAuthService {
    /// <summary>
    /// Adds a new user if one doesn't already exist and throws an error if they do. Should 
    /// only be used in the sign-up process.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    Task AddUserAsync(string accountName, string defaultPassword, int defaultRole);

    /// <summary>
    /// Adds a new line to the API key table.
    /// </summary>
    /// <returns>API key</returns>
    Task<string> NewSignInAsync(string accountName);

    /// <summary>
    /// <c>For Debug Only</c>, I wouldn't reccommend assigning this an endpoint. Returns all users sorted by 
    /// ID. Swallows errors and returns an empty list. 
    /// </summary>
    Task<IEnumerable<Account>> GetAllUsersAsync();

    /// <summary>
    /// Returns the user object from the given account. Throws an exception if the user does not exist.
    /// </summary>
    Task<Account> GetUserAsync(string account);

    /// <summary>
    /// Returns a date for when the API key was last updated in the <c>validatedOn</c> field.
    /// Throws an exception if no API key exists in the table. 
    /// </summary>
    /// <param name="accountName">Account used</param>
    /// <param name="key">API Key</param>
    /// <returns>Null or DateTime</returns>
    Task<DateTime> GetValidatedOnForKeyAsync(string accountName, string key);

    /// <summary>
    /// Returns True if the username and password match what's stored in the database. This 
    /// handles errors thrown by invalid users and simply returns False.
    /// </summary>
    /// <returns>If the hashed password equals the stored hash</returns>
    Task<bool> IsValidUserPassAsync(string accountName, string password);

    /// <summary>
    /// Updates the api key with the current DateTime value. This allows recently 
    /// signed-in users to continue being signed in on their key. It's primarily 
    /// used by my IdentityMiddleware and not recommended you use it on its own.
    /// </summary>
    Task ReValidateAsync(string accountId, string key);

    /// <summary>
    /// Updates the user's password in the table. Does not affect any of the API keys currently
    /// entered. 
    /// </summary>
    Task UpdatePasswordAsync(string accountName, string newPassword);

    /// <summary>
    /// Updates the user's role in the table. Does not affect any current keys.
    /// Does update the lookup dictionary with the new role. 
    /// </summary>
    Task UpdateRoleAsync(string accountName, int newRole);

    /// <summary>
    /// Deletes all sign-in records by the user and their place in the User table.
    /// </summary>
    Task DeleteUserAsync(string accountId);

    /// <summary>
    /// Signs a user out globally (all keys are deleted), such as in the instance 
    /// of someone else gaining access to their account.
    /// </summary>
    Task GlobalSignOutAsync(string accountId);

    /// <summary>
    /// Sign out on an individual key. 
    /// </summary>
    Task KeySignOutAsync(string accountId, string key);

    /// <summary>
    /// Given the TimeSpan, remove keys from any user that are older than that length.
    /// </summary>
    Task ExpiredKeySignOutAsync(TimeSpan length);

    /// <summary>
    /// Returns the Guid of a given account name. 
    /// </summary>
    Task<Guid> GetGuidAsync(string account);

    /// <summary>
    /// Returns the Role of a given account name. 
    /// </summary>
    Task<int> GetRoleAsync(string account);

    /// <summary>
    /// Retrieves the current number of sessions for a given user. 
    /// </summary>
    Task<int> GetCurrentSessionCountAsync(string account);

    /// <summary>
    /// Returns the first <c>limit</c> users, given their AccountName, from the query. 
    /// The query checks Contains, so in SQL '%{query}%'.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAsync(string query, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role greater than the given provided role. 
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAboveRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role greater than or equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAboveOrAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role less than or equal to the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersBelowOrAtRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the first <c>limit</c> users with a role less than the given provided role.
    /// </summary>
    Task<IEnumerable<Account>> QueryUsersBelowRoleAsync(int role, int limit);

    /// <summary>
    /// Gets the account name for the given user ID (Guid).
    /// </summary>
    Task<string> GetAccountNameAsync(Guid account);
}
