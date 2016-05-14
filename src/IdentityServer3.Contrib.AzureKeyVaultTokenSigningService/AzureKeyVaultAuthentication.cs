using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace IdentityServer3.Contrib.AzureKeyVaultTokenSigningService
{
    internal class AzureKeyVaultAuthentication
    {
        private readonly string _clientId;
        private readonly string _clientSecret;

        public AzureKeyVaultAuthentication(string clientId, string clientSecret)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
        }
        
        internal async Task<string> KeyVaultClientAuthenticationCallback(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_clientId, _clientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
    }
}
