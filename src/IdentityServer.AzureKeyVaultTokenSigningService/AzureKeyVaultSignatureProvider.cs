using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;

namespace IdentityServer.AzureKeyVaultTokenSigningService
{
    public class AzureKeyVaultSignatureProvider : SignatureProvider
    {
        private readonly string _keyIdentifier;
        private readonly string _algorithm;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly KeyVaultClient _keyVaultClient;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyIdentifier"></param>
        /// <param name="algorithm">A valid and supported <see cref="JsonWebKeySignatureAlgorithm"/> value. Note: <see cref="JsonWebKeySignatureAlgorithm.RSNULL"/> is not supported.</param>
        /// <param name="keyVaultAuthenticationCallback"></param>
        /// <exception cref="ArgumentException">RSNULL is not allowed in this scenario.</exception>
        /// <exception cref="ArgumentException">Supplied value is not a currently supported JsonWebKeySignatureAlgorithm value.</exception>
        public AzureKeyVaultSignatureProvider(string keyIdentifier, string algorithm, KeyVaultClient.AuthenticationCallback keyVaultAuthenticationCallback) : this(keyIdentifier, algorithm, new KeyVaultClient(keyVaultAuthenticationCallback))
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyIdentifier"></param>
        /// <param name="algorithm">A valid and supported <see cref="JsonWebKeySignatureAlgorithm"/> value. Note: <see cref="JsonWebKeySignatureAlgorithm.RSNULL"/> is not supported.</param>
        /// <param name="keyVaultClient"></param>
        /// <exception cref="ArgumentException">RSNULL is not allowed in this scenario.</exception>
        /// <exception cref="ArgumentException">Supplied value is not a currently supported JsonWebKeySignatureAlgorithm value.</exception>
        public AzureKeyVaultSignatureProvider(string keyIdentifier, string algorithm, KeyVaultClient keyVaultClient)
        {
            _keyIdentifier = keyIdentifier;
            _algorithm = algorithm;
            switch (algorithm)
            {
                case JsonWebKeySignatureAlgorithm.RS256:
                    _hashAlgorithm = SHA256.Create();
                    break;
                case JsonWebKeySignatureAlgorithm.RS384:
                    _hashAlgorithm = SHA384.Create();
                    break;
                case JsonWebKeySignatureAlgorithm.RS512:
                    _hashAlgorithm = SHA512.Create();
                    break;
                case JsonWebKeySignatureAlgorithm.RSNULL:
                    throw new ArgumentException("RSNULL is not allowed in this scenario.", algorithm);
                default:
                    throw new ArgumentException(algorithm + " is not a currently supported JsonWebKeySignatureAlgorithm value.", algorithm);
            }
            _keyVaultClient = keyVaultClient;
        }

        public override byte[] Sign(byte[] input)
        {
            var digest = _hashAlgorithm.ComputeHash(input);
            return _keyVaultClient.SignAsync(_keyIdentifier, _algorithm, digest).Result.Result;
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            // TODO: If the public key is available offline (cached in memory?) verify this offline to save money and perform this operation faster
            var digest = _hashAlgorithm.ComputeHash(input);
            return _keyVaultClient.VerifyAsync(_keyIdentifier, _algorithm, digest, signature).Result;
        }

        protected override void Dispose(bool disposing) => Dispose();
    }
}
