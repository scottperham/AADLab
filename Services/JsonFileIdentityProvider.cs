using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AADLab.Services
{
    // A fake identity provider that uses a JSON file as it's backing store
    // this could be replaced with an implementation that uses a _real_
    // identity provider
    public class JsonFileIdentityProvider : IIdentityProvider
    {
        readonly string _filePath;
        List<UserIdentity> _cached = null;
        DateTime _cacheUpdated = DateTime.UtcNow;

        readonly JsonSerializerOptions _serializerOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public JsonFileIdentityProvider()
        {
            _filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data\\identities.json");
        }

        // Populates the local cache from the JSON file if it's either empty
        // or the file has been updated since the last cache
        async Task PopulateCache()
        {
            if (_cached == null || File.GetLastWriteTimeUtc(_filePath) > _cacheUpdated)
            {
                if (!File.Exists(_filePath))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_filePath));
                    await File.WriteAllTextAsync(_filePath, "[]");
                }

                using var fileStream = File.Open(_filePath, FileMode.OpenOrCreate);

                _cached = await JsonSerializer.DeserializeAsync<List<UserIdentity>>(fileStream, _serializerOptions);
                _cacheUpdated = File.GetLastWriteTimeUtc(_filePath);
            }
        }

        // Writes the cache back to the JSON file
        async Task<bool> CommitCache()
        {
            if (File.GetLastWriteTimeUtc(_filePath) > _cacheUpdated)
            {
                return false;
            }

            using var fileStream = File.Open(_filePath, FileMode.Truncate);

            await JsonSerializer.SerializeAsync(fileStream, _cached, _serializerOptions);

            _cacheUpdated = File.GetLastWriteTimeUtc(_filePath);
            return true;
        }

        // Returns a user identity by id
        public async Task<UserIdentity> GetUserById(string id)
        {
            await PopulateCache();

            return _cached.FirstOrDefault(x => x.Id.Equals(id));
        }

        // Returns a user identity by AAD object id and tenant id
        public async Task<UserIdentity> GetUserByOidAndTid(string oid, string tid)
        {
            await PopulateCache();

            return _cached.FirstOrDefault(x => x.AADOID?.Equals(oid) == true && x.AADTID?.Equals(tid) == true);
        }

        // Returns a user by email address
        public async Task<UserIdentity> GetLocalUserByEmail(string email)
        {
            await PopulateCache();

            return _cached.FirstOrDefault(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(x.Password));
        }

        // Returns all users in the system
        public async Task<UserIdentity[]> GetAllUsers()
        {
            await PopulateCache();

            return _cached.ToArray();
        }

        // Returns a user by a given refresh token
        public async Task<UserIdentity> GetUserByRefreshToken(string refreshToken)
        {
            await PopulateCache();

            return _cached.FirstOrDefault(x => x.RefreshTokens.FirstOrDefault(y => y.Token == refreshToken && y.AbsoluteExpiryUtc > DateTime.UtcNow) != null);
        }

        // Adds or updates a user, updates the cache and commits to the JSON file
        public async Task CreateOrUpdateUser(UserIdentity user)
        {
            await PopulateCache();

            var userIndex = _cached.FindIndex(x => x.Id.Equals(user.Id));

            if (userIndex != -1)
            {

                _cached.RemoveAt(userIndex);
                _cached.Insert(userIndex, user);
            }
            else
            {
                _cached.Add(user);
            }

            await CommitCache();
        }

        // Removes a user from the system
        public async Task DeleteUser(string id)
        {
            await PopulateCache();

            _cached.RemoveAll(x => x.Id.Equals(id));
        }
    }
}
