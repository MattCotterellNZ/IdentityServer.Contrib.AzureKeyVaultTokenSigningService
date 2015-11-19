using System;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using AuthenticationContext = Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext;

namespace IdentityServer.AzureKeyVaultTokenSigningService
{
    // This project can output the Class library as a NuGet Package.
    // To enable this option, right-click on the project and select the Properties menu item. In the Build tab select "Produce outputs on build".
    public class AzureKeyVaultTokenSigningService : ITokenSigningService
    {
        private readonly string _keyIdentifier;
        private readonly string _keyVaultClientId;
        private readonly string _keyVaultClientSecret;

        /// <summary>
        /// Initializes a new instance of the <see cref="AzureKeyVaultTokenSigningService"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="keyIdentifier"></param>
        /// <param name="keyVaultClientId"></param>
        /// <param name="keyVaultClientSecret"></param>
        public AzureKeyVaultTokenSigningService(string keyIdentifier, string keyVaultClientId, string keyVaultClientSecret)
        {
            _keyIdentifier = keyIdentifier;
            _keyVaultClientId = keyVaultClientId;
            _keyVaultClientSecret = keyVaultClientSecret;
        }

        /// <summary>
        /// Signs the token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        /// A protected and serialized security token
        /// </returns>
        /// <exception cref="System.InvalidOperationException">Invalid token type</exception>
        public virtual Task<string> SignTokenAsync(Token token)
        {
            return Task.FromResult(CreateJsonWebToken(token, _keyIdentifier));
        }

        /// <summary>
        /// Creates the json web token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="keyIdentifier">The Azure Key Vault key identifier.</param>
        /// <returns></returns>
        protected virtual string CreateJsonWebToken(Token token, string keyIdentifier)
        {
            var jwt = new JwtSecurityToken(
                token.Issuer,
                token.Audience,
                token.Claims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddSeconds(token.Lifetime)
            );

            // amr is an array - if there is only a single value turn it into an array
            if (jwt.Payload.ContainsKey("amr"))
            {
                var amrValue = jwt.Payload["amr"] as string;
                if (amrValue != null)
                {
                    jwt.Payload["amr"] = new string[] { amrValue };
                }
            }

            var rawDataBytes = System.Text.Encoding.UTF8.GetBytes(jwt.RawHeader + "." + jwt.RawPayload); // TODO: Is UTF-8 correct?

            var keyVaultSignatureProvider = new AzureKeyVaultSignatureProvider(keyIdentifier, JsonWebKeySignatureAlgorithm.RS256, KeyVaultClientSecretAuthenticationCallback);

            var rawSignature = Convert.ToBase64String(keyVaultSignatureProvider.Sign(rawDataBytes));

            return jwt.RawHeader + "." + jwt.RawPayload + "." + rawSignature;
        }

        private async Task<string> KeyVaultClientSecretAuthenticationCallback(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_keyVaultClientId, _keyVaultClientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
    }
}
