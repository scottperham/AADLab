using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace AADLab.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GetToken(string id, string name, string email, IDictionary<string, string> additionalClaims = null)
        {
            var claims = new List<Claim>
            {
                new Claim("nameidentifier", id),
                new Claim("name", name),
                new Claim("emailaddress", email)
            };

            var handler = new JwtSecurityTokenHandler();

            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], _configuration["Jwt:Audience"], claims, DateTime.UtcNow.AddSeconds(-1), DateTime.UtcNow.AddMinutes(20),
                new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"])), SecurityAlgorithms.HmacSha256Signature));

            return handler.WriteToken(token);
        }

        public RefreshToken GetRefreshToken()
        {
            return new RefreshToken
            {
                Token = Guid.NewGuid().ToString(),
                AbsoluteExpiryUtc = DateTime.UtcNow.AddMinutes(5)
            };
        }
    }
}
