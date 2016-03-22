using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4.Core.Services;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.OptionsModel;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace IdentityServer4.Contrib.AzureKeyVaultTokenSigningService
{
    public class AzureKeyVaultSigningKeyService : ISigningKeyService
    {
        private readonly AzureKeyVaultTokenSigningServiceOptions _options;
        private byte[] _keyVaultKeyExponent;
        private byte[] _keyVaultKeyModulus;

        /// <summary>
        /// Initializes a new instance of the <see cref="AzureKeyVaultTokenSigningService"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public AzureKeyVaultSigningKeyService(IOptions<AzureKeyVaultTokenSigningServiceOptions> options)
        {
            _options = options.Value;
        }

        public async Task<X509Certificate2> GetSigningKeyAsync()
        {
            return await GetX509Certificate();
        }

        public async Task<IEnumerable<X509Certificate2>> GetValidationKeysAsync()
        {
            var x509 = await GetX509Certificate();
            return new List<X509Certificate2>{x509};
        }

        public Task<string> GetKidAsync(X509Certificate2 certificate)
        {
            return Task.FromResult(_options.KeyIdentifier);
        }

        private async Task<X509Certificate2> GetX509Certificate()
        {
            var keyVaultClient = new KeyVaultClient(KeyVaultClientAuthenticationCallback);
            var keyBundle = await keyVaultClient.GetKeyAsync(_options.KeyIdentifier).ConfigureAwait(false);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(new RSAParameters
            {
                Exponent = keyBundle.Key.E,
                Modulus = keyBundle.Key.N,
            });

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.N);
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E);

                    //All Parameter Must Have Value so Set Other Parameter Value Whit Invalid Data  (for keeping Key Structure  use "parameters.Exponent" value for invalid data)
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.D
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.P
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.Q
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.DP
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.DQ
                    EncodeIntegerBigEndian(innerWriter, keyBundle.Key.E); // instead of parameters.InverseQ

                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return new X509Certificate2(stream.GetBuffer());
            }
        }

        private async Task<string> KeyVaultClientAuthenticationCallback(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(_options.ClientId, _options.ClientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
    }
}
