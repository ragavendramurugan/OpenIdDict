using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIdDict.Controllers
{
    [ApiExplorerSettings(IgnoreApi = true)]
    public class AuthenticationController : ControllerBase
    {
        private List<AuthUser> userList = new List<AuthUser>();

        public AuthenticationController()
        {
            for (var i = 1; i <= 10; i++)
            {
                userList.Add(new AuthUser
                {
                    Id = i,
                    Username = $"User {i}",
                    Password = $"pass{i}",
                    Email = $"user{i}@dummy.com",
                    UserRoles = new string[] { i % 2 == 0 ? "Admin" : "User" }
                });
            }
        }

        [HttpPost("~/connect/token")]
        [Consumes("application/x-www-form-urlencoded")]
        [Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var oidcRequest = HttpContext.GetOpenIddictServerRequest();
            if (oidcRequest.IsPasswordGrantType())
                return TokensForPasswordGrantType(oidcRequest);

            if (oidcRequest.IsRefreshTokenGrantType())
                return await TokensForRefreshGrantType(oidcRequest);            

            return BadRequest(new OpenIddictResponse
            {
                Error = OpenIddictConstants.Errors.UnsupportedGrantType
            });
        }

        //private async Task<IActionResult> TokensForPasswordGrantType(OpenIddictRequest request)
        private IActionResult TokensForPasswordGrantType(OpenIddictRequest request)
        {
            //var user = await _userManager.FindByNameAsync(request.Username);
            //if (user == null)
            //    return Unauthorized();
            var user = userList.FirstOrDefault(x => x.Email == request.Username);
            if (user == null)
                return Unauthorized();

            //var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            var signInResult = userList.Any(x => x.Email == request.Username && x.Password == request.Password);
            //if (signInResult.Succeeded)
            if (signInResult)
            {
                var identity = new ClaimsIdentity(
                    TokenValidationParameters.DefaultAuthenticationType,
                    OpenIddictConstants.Claims.Name,
                    OpenIddictConstants.Claims.Role);

                identity.AddClaim(OpenIddictConstants.Claims.Subject, user.Id.ToString(), OpenIddictConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIddictConstants.Claims.Username, user.Username, OpenIddictConstants.Destinations.AccessToken);
                // Add more claims if necessary

                foreach (var userRole in user.UserRoles)
                {
                    //identity.AddClaim(OpenIddictConstants.Claims.Role, userRole.Role.NormalizedName, OpenIddictConstants.Destinations.AccessToken);
                    identity.AddClaim(OpenIddictConstants.Claims.Role, userRole, OpenIddictConstants.Destinations.AccessToken);
                }

                var claimsPrincipal = new ClaimsPrincipal(identity);
                //claimsPrincipal.SetScopes(new string[]
                //{
                //    OpenIddictConstants.Scopes.Roles,
                //    OpenIddictConstants.Scopes.OfflineAccess,
                //    OpenIddictConstants.Scopes.Email,
                //    OpenIddictConstants.Scopes.Profile,
                //});
                claimsPrincipal.SetScopes(new string[]
                {
                    OpenIddictConstants.Scopes.OfflineAccess
                });

                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            else
                return Unauthorized();
        }

        private async Task<IActionResult> TokensForRefreshGrantType(OpenIddictRequest request)
        {
            // Retrieve the claims principal stored in the refresh token.
            var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Retrieve the user profile corresponding to the refresh token.
            // Note: if you want to automatically invalidate the refresh token
            // when the user password/roles change, use the following line instead:
            // var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
            //var user = await _userManager.GetUserAsync(info.Principal);
            //if (user == null)
            if (!info.Succeeded)
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The refresh token is no longer valid."
                });

                return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // Create a new ClaimsPrincipal containing the claims that
            // will be used to create an id_token, a token or a code.
            //var principal = await _signInManager.CreateUserPrincipalAsync(user);

            //foreach (var claim in principal.Claims)
            foreach (var claim in info.Principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, info.Principal));
            }

            return SignIn(info.Principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            switch (claim.Type)
            {
                case Claims.Name:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Profile))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Email:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Email))
                        yield return Destinations.IdentityToken;

                    yield break;

                case Claims.Role:
                    yield return Destinations.AccessToken;

                    if (principal.HasScope(Scopes.Roles))
                        yield return Destinations.IdentityToken;

                    yield break;

                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                case "AspNet.Identity.SecurityStamp": yield break;

                default:
                    yield return Destinations.AccessToken;
                    yield break;
            }
        }
    }

    public class AuthUser
    {
        public int Id { get; set; }
        public String Username { get; set; }
        public String Email { get; set; }
        public String Password { get; set; }
        public string[] UserRoles { get; set; }
    }
}
