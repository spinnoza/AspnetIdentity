using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace IdentityServer
{
    public class Configuration
    {

        public static IEnumerable<IdentityResource> GetIdentityResources() =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
               new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiScope> GetScopes() =>
         new List<ApiScope>
        {
            new ApiScope
            {
                Name = "ApiOne",
               
            },
            new ApiScope
            {
                Name = "ApiTwo",
              
            },
        };

        public static IEnumerable<Client> GetClients() =>
            new List<Client> {
                new Client {
                    ClientId = "client_id",
                    ClientSecrets = { new Secret("client_secret".ToSha256()) },

                    AllowedGrantTypes = GrantTypes.ClientCredentials,

                    AllowedScopes = { "ApiOne" }
                },
                new Client {
                    ClientId = "client_id_mvc",
                    ClientSecrets = { new Secret("client_secret_mvc".ToSha256()) },

                    AllowedGrantTypes = GrantTypes.Code,

                    RedirectUris = { "https://localhost:7240/signin-oidc" },

                    AllowedScopes = {
                        "ApiOne",
                        "ApiTwo",

                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                    },
                    RequireConsent = false,
                }


            };
    }

   
}

