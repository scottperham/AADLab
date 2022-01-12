using AADLab.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AADLab.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ApiController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly IIdentityProvider _identityProvider;
        private readonly DateTime _epoch = new DateTime(1970, 1, 1);
        private readonly Graph _graph;

        public ApiController(ITokenService tokenService, IIdentityProvider identityProvider, IConfiguration configuration)
        {
            _tokenService = tokenService;
            _identityProvider = identityProvider;

            _graph = new Graph(configuration);
        }

        static string ComputePasswordHash(string password, string email)
        {
            var byteResult = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(email.ToLower()));

            return Convert.ToBase64String(byteResult.GetBytes(24));
        }

        LoginResult GetLoginResult(UserIdentity identity, RefreshToken refreshToken, string graphToken = null, bool requireLink = false)
        {
            var loginResult = new LoginResult
            {
                DisplayName = identity.DisplayName,
                GraphAccessToken = graphToken,
                RequireLink = requireLink
            };

            if (!requireLink)
            {
                loginResult.TokenExpiry = (int)(refreshToken.AbsoluteExpiryUtc - _epoch).TotalSeconds;
                loginResult.RefreshToken = refreshToken.Token;
                loginResult.AccessToken = _tokenService.GetToken(identity.Id, identity.DisplayName, identity.Email);
            }

            return loginResult;
        }

        [HttpPost("SignUp")]
        public async Task<IActionResult> SignUp([FromBody] CreateUserRequest request)
        {
            //Find the user by email address to see if they already have an account
            var identity = await _identityProvider.GetLocalUserByEmail(request.Email);

            if (identity != null)
            {
                return BadRequest("Email address already exists");
            }

            //Create a new identity
            identity = new UserIdentity
            {
                Id = Guid.NewGuid().ToString(),
                DisplayName = request.DisplayName,
                Email = request.Email,
                Password = ComputePasswordHash(request.Password, request.Email),
                RefreshTokens = new List<RefreshToken>()
            };

            //Save!
            await _identityProvider.CreateOrUpdateUser(identity);

            return Ok();
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> LoginRefresh([FromBody] RefreshLoginRequest loginRequest)
        {
            //Find the identity linked to the refresh token
            var identity = await _identityProvider.GetUserByRefreshToken(loginRequest.Token);

            if (identity == null)
            {
                return NotFound();
            }

            //Generate a new refresh token
            var refreshToken = _tokenService.GetRefreshToken();

            //Remove the old refresh token and persist the new one
            identity.RemoveRefreshToken(loginRequest.Token);
            identity.AddRefreshToken(refreshToken);

            //Save!
            await _identityProvider.CreateOrUpdateUser(identity);

            return Ok(GetLoginResult(identity, refreshToken));
        }

        [HttpPost("LoginLocal")]
        public async Task<IActionResult> LoginLocally([FromBody] LocalLoginRequest request)
        {
            //Noddy validation for email and password
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest("You must specify both email and password");
            }

            //Find the identity by email address
            var identity = await _identityProvider.GetLocalUserByEmail(request.Email);

            if (identity == null)
            {
                return BadRequest("Email not found or password incorrect");
            }

            //Because we don't store passwords in clear text (in case of data breach)
            //Hash the passed password
            var hashedPassword = ComputePasswordHash(request.Password, identity.Email);

            //See if it matches
            if (hashedPassword != identity.Password)
            {
                return BadRequest("Email not found or password incorrect");
            }

            //Generate a new refresh token
            var refreshToken = _tokenService.GetRefreshToken();

            identity.AddRefreshToken(refreshToken);

            //Save!
            await _identityProvider.CreateOrUpdateUser(identity);

            return Ok(GetLoginResult(identity, refreshToken));
        }

        private async Task<LoginResult> LoginWithTokenInternal(string accessToken, bool shouldLink, bool saveLink)
        {
            //The AAD token we got from login only has a access_as_user scope
            //Swap it for a token that has the scopes we're actually interested in
            var graphAccessToken = await _graph.GetOnBehalfOfToken(accessToken);

            //Get some info from Graph using the new token
            var me = await _graph.GetMe(graphAccessToken);
            var org = await _graph.GetOrganisation(graphAccessToken);

            //Find the identity based on the AAD object ID and tenant ID
            var identity = await _identityProvider.GetUserByOidAndTid(me.Id, org.Value[0].Id);

            //If there isn't one...
            if (identity == null)
            {
                //Find the user by email
                identity = await _identityProvider.GetLocalUserByEmail(me.Mail);

                if (identity != null)
                {
                    if (!shouldLink)
                    {
                        //Do link flow...
                        return GetLoginResult(identity, null, graphAccessToken, true);
                    }

                    if (saveLink)
                    {
                        //Link!
                        identity.AADOID = me.Id;
                        identity.AADTID = org.Value[0].Id;
                    }
                    else
                    {
                        identity = null;
                    }
                }

                //No user at all...
                //fall through to create a new one
            }

            //Create new identity if there wasn't one found
            identity ??= new UserIdentity
            {
                Id = Guid.NewGuid().ToString(),
                DisplayName = me.DisplayName,
                Email = me.Mail,
                AADOID = me.Id,
                AADTID = org.Value[0].Id,
                RefreshTokens = new List<RefreshToken>()
            };

            //Generate a new refresh token
            var refreshToken = _tokenService.GetRefreshToken();

            identity.AddRefreshToken(refreshToken);

            //Save!
            await _identityProvider.CreateOrUpdateUser(identity);

            return GetLoginResult(identity, refreshToken, graphAccessToken);
        }

        [HttpPost("LinkWithIdentity")]
        public async Task<IActionResult> LinkWithIdentity([FromBody] LinkLoginRequest request)
        {
            var result = await LoginWithTokenInternal(request.AccessToken, true, request.Link);

            return Ok(result);
        }

        [HttpPost("LoginWithToken")]
        public async Task<IActionResult> LoginWithToken([FromBody] TokenLoginRequest request)
        {
            var result = await LoginWithTokenInternal(request.AccessToken, false, false);

            return Ok(result);
        }

        [HttpGet("Users")]
        [Authorize]
        public async Task<IActionResult> GetUsers()
        {
            var identities = await _identityProvider.GetAllUsers();

            return Ok(identities.Select(x => new UserIdentityResult
            {
                Id = x.Id,
                Email = x.Email,
                DisplayName = x.DisplayName,
                AADLinked = x.LinkedToAAD,
                LocalAccount = !string.IsNullOrEmpty(x.Password)
            }));
        }

        [HttpPost("Users/Delete")]
        [Authorize]
        public async Task<IActionResult> DeleteUser([FromBody] DeleteUserRequest request)
        {
            await _identityProvider.DeleteUser(request.Email);

            return Ok();
        }

        [HttpPost("Profile")]
        [Authorize]
        public async Task<IActionResult> GetProfile([FromBody] GetProfileRequest request)
        {
            //Pull out the nameidentifier claim from the token
            var idClaim = User.FindFirst("nameidentifier");

            //Find the identity
            var identity = await _identityProvider.GetUserById(idClaim.Value);

            GraphMeResult microsoftIdentity = null;

            //If we've passed an AAD access token
            if (!string.IsNullOrEmpty(request.AccessToken))
            {
                //Swap the token
                var graphAccessToken = await _graph.GetOnBehalfOfToken(request.AccessToken);

                //Get user info from Graph
                microsoftIdentity = await _graph.GetMe(graphAccessToken);
            }

            return Ok(new
            {
                LocalIdentity = identity,
                MicrosoftIdentity = microsoftIdentity
            });
        }
    }

    public class GetProfileRequest
    {
        public string AccessToken { get; set; }
    }
}
