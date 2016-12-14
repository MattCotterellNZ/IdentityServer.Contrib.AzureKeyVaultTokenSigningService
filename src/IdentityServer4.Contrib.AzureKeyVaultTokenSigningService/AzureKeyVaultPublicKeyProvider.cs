using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityServer.Contrib.JsonWebKeyAdapter;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace IdentityServer4.Contrib.AzureKeyVaultTokenSigningService
{
    public class AzureKeyVaultPublicKeyProvider : IPublicKeyProvider
    {
        private readonly AzureKeyVaultTokenSigningServiceOptions _options;
        private readonly AzureKeyVaultAuthentication _authentication;
        private JsonWebKey _jwk;

        /// <summary>
        /// Initializes a new instance of the <see cref="AzureKeyVaultTokenSigningService"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public AzureKeyVaultPublicKeyProvider(IOptions<AzureKeyVaultTokenSigningServiceOptions> options)
        {
            _options = options.Value;
            _authentication = new AzureKeyVaultAuthentication(_options.ClientId, _options.ClientSecret);
        }

        public async Task<IEnumerable<JsonWebKey>> GetAsync()
        {
            if (_jwk == null)
            {
                var keyVaultClient = new KeyVaultClient(_authentication.KeyVaultClientAuthenticationCallback);
                var keyBundle = await keyVaultClient.GetKeyAsync(_options.KeyIdentifier).ConfigureAwait(false);
                _jwk = new JsonWebKey(keyBundle.Key.ToString());
            }
            
            return new List<JsonWebKey> { _jwk };
        }
    }
}
