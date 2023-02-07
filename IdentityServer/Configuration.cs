using Duende.IdentityServer.Models;
using IdentityModel;

namespace IdentityServer
{
    public class Configuration
    {
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
                }
            };
    }

   
}

