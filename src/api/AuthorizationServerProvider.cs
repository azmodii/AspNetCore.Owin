using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace API
{
    public class AuthorizationProvider : OpenIdConnectServerProvider
    {
        public override Task ValidateTokenRequest(ValidateTokenRequestContext context)
        {
            // Reject the token request that don't use grant_type=password or grant_type=refresh_token.
            if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only resource owner password credentials and refresh token " +
                                 "are accepted by this authorization server");
                return Task.FromResult(0);
            }

            // Since there's only one application and since it's a public client
            // (i.e a client that cannot keep its credentials private), call Skip()
            // to inform the server that the request should be accepted without 
            // enforcing client authentication.
            context.Skip();
            return Task.FromResult(0);
        }

        public override Task HandleTokenRequest(HandleTokenRequestContext context)
        {
            if (!context.Request.IsPasswordGrantType()) return Task.FromResult(0);

            // "There was a server error while trying to validate the authentication.");
            if (!context.Request.Username.Equals("hello")) { 
                context.Reject("authentication error. Username must be 'hello'");
                return Task.FromResult(0);
            }
            // "There was a server error while trying to validate the authentication.");
            if (!context.Request.Password.Equals("world"))
            {
                context.Reject("authentication error. Password must be 'world'");
                return Task.FromResult(0);
            }

            var identity = new ClaimsIdentity(context.Scheme.Name);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "userID");
                
            // When adding custom claims, you MUST specify one or more destinations.
            // Read "part 7" for more information about custom claims and scopes.
            /*
                * foreach(var data in authenticatedData.GetData())
            {
                identity.AddClaim(data.Key, data.Value, OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);
            }*/
                
            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity), new AuthenticationProperties() {  AllowRefresh = true },
                context.Scheme.Name);
                
            // Set the list of scopes granted to the client application. OfflineAccess will return the refresh token
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OfflineAccess, OpenIdConnectConstants.Scopes.Profile);
               
            // Set the resource servers the access token should be issued for.
            ticket.SetResources("resource_server");
            context.Validate(ticket);
            return Task.FromResult(0);
            
        }
    }
}
