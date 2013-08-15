using System.Diagnostics;
using System.Runtime.Remoting.Messaging;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using ServerApp;

[assembly: OwinStartup(typeof(Startup))]

namespace ServerApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "App",
                LoginPath = "/Login",
            });

            app.UseGoogleAuthentication(new GoogleAuthenticationOptions
            {
                SignInAsAuthenticationType = "App",
                Provider = new GoogleAuthenticationProvider
                {
                    OnAuthenticated = async ctx =>
                    {
                        var claim = new Claim("account_id", "654321");
                        ctx.Identity.AddClaim(claim);
                    }
                }
            });

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = "/Authorize",
                TokenEndpointPath = "/Token",
                Provider = new OAuthAuthorizationServerProvider
                {
                    OnValidateClientRedirectUri = ValidateClientRedirectUriAsync,
                    OnValidateClientAuthentication = ValidateClientAuthenticationAsync
                },
                AuthorizationCodeProvider = new SingleUseInMemoryNonceProvider()
            });

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
            });
        }

        public async Task ValidateClientRedirectUriAsync(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == "the-client")
            {
                context.Validated("http://localhost:9002/Show/Return");
            }
            else if (context.ClientId == "readme-page")
            {
                context.Validated("/ReadMe");
            }
        }

        public async Task ValidateClientAuthenticationAsync(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                if (clientId == "the-client" && clientSecret == "the-client-secret")
                {
                    context.Validated(clientId);
                }
            }
        }
    }
}
