using System.Threading.Tasks;

namespace AADLab.Services
{
    public interface IIdentityProvider
    {
        Task<UserIdentity> GetUserById(string id);
        Task<UserIdentity> GetLocalUserByEmail(string email);
        Task<UserIdentity> GetUserByOidAndTid(string oid, string tid);
        Task<UserIdentity[]> GetAllUsers();
        Task CreateOrUpdateUser(UserIdentity user);
        Task<UserIdentity> GetUserByRefreshToken(string refreshToken);
        Task DeleteUser(string email);
    }
}
