using System;
using System.IdentityModel.Tokens;

namespace IdentityServer.AzureKeyVaultTokenSigningService
{
    public class AzureKeyVaultSigningCredentials : SigningCredentials
    {
        public AzureKeyVaultSigningCredentials(RsaSecurityKey signingKey, string digestAlgorithm, SecurityKeyIdentifier signingKeyIdentifier = null) : base(signingKey, SecurityAlgorithms.RsaSha256Signature, digestAlgorithm, signingKeyIdentifier)
        {
            if (signingKey.HasPrivateKey())
            {
                throw new ArgumentException("For security reasons, the signing key cannot contain the private key. Please remove all traces of this from the application and defer to Azure Key Vault for signing.", nameof(signingKey));
            }

            if (digestAlgorithm != SecurityAlgorithms.Sha256Digest && digestAlgorithm != SecurityAlgorithms.Sha512Digest)
            {
                throw new ArgumentOutOfRangeException(nameof(digestAlgorithm), digestAlgorithm, "Only SHA256 and SHA512 are supported at this time.");
            }
        }
    }
}
