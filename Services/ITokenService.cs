using System.Collections.Generic;

namespace AADLab.Services
{
    public interface ITokenService
    {
        string GetToken(string id, string name, string email, IDictionary<string, string> additionalClaims = null);
        RefreshToken GetRefreshToken();
    }
}
