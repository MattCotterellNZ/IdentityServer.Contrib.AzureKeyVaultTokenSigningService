﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using IdentityServer4.Core.Models;
using IdentityServer4.Core.Services;
using Newtonsoft.Json.Linq;
using System.Linq;
using IdentityModel;
using IdentityServer.Contrib.JsonWebKeyAdapter;
using IdentityServer4.Core;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Extensions.OptionsModel;

namespace IdentityServer4.Contrib.AzureKeyVaultTokenSigningService
{
    // This project can output the Class library as a NuGet Package.
    // To enable this option, right-click on the project and select the Properties menu item. In the Build tab select "Produce outputs on build".
    public class AzureKeyVaultTokenSigningService : ITokenSigningService
    {
        private readonly IPublicKeyProvider _publicKeyProvider;
        private readonly AzureKeyVaultTokenSigningServiceOptions _options;
        private readonly AzureKeyVaultAuthentication _authentication;

        /// <summary>
        /// Initializes a new instance of the <see cref="AzureKeyVaultTokenSigningService"/> class.
        /// </summary>
        /// <param name="publicKeyProvider">The public key provider.</param>
        /// <param name="options">The options.</param>
        public AzureKeyVaultTokenSigningService(IPublicKeyProvider publicKeyProvider, IOptions<AzureKeyVaultTokenSigningServiceOptions> options)
        {
            _publicKeyProvider = publicKeyProvider;
            _options = options.Value;
            _authentication = new AzureKeyVaultAuthentication(_options.ClientId, _options.ClientSecret);
        }

        /// <summary>
        /// Signs the token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>
        /// A protected and serialized security token
        /// </returns>
        public virtual async Task<string> SignTokenAsync(Token token)
        {
            var credentials = await GetSigningCredentialsAsync();
            return await CreateJsonWebToken(token, credentials);
        }

        /// <summary>
        /// Retrieves the signing credential (override to load key from alternative locations)
        /// </summary>
        /// <returns>The signing credential</returns>
        protected virtual async Task<AzureKeyVaultSigningCredentials> GetSigningCredentialsAsync()
        {
            var jwk = (await _publicKeyProvider.GetAsync()).FirstOrDefault();
            if (jwk == null) throw new Exception("The public key provider service did not return a key."); // TODO: What's better than Exception? SecurityTokenSignatureKeyNotFoundException maybe?

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Exponent = FromBase64Url(jwk.E),
                Modulus = FromBase64Url(jwk.N),
            });
            var securityKey = new RsaSecurityKey(rsa);

            return new AzureKeyVaultSigningCredentials(securityKey, SecurityAlgorithms.Sha256Digest);
        }

        /// <summary>
        /// Creates the json web token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="credentials">The credentials.</param>
        /// <returns>The signed JWT</returns>
        protected virtual async Task<string> CreateJsonWebToken(Token token, AzureKeyVaultSigningCredentials credentials)
        {
            var header = await CreateHeaderAsync(token, credentials);
            var payload = await CreatePayloadAsync(token);

            return await SignAsync(new JwtSecurityToken(header, payload));
        }

        /// <summary>
        /// Creates the JWT header
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="keyVaultCredentials">The credentials.</param>
        /// <returns>The JWT header</returns>
        protected virtual Task<JwtHeader> CreateHeaderAsync(Token token, AzureKeyVaultSigningCredentials keyVaultCredentials)
        {
            var header = new JwtHeader(keyVaultCredentials);
            if (keyVaultCredentials != null)
            {
                header.Add("kid", _options.KeyIdentifier);
                header.Add("x5t", _options.KeyIdentifier);
            }

            return Task.FromResult(header);
        }

        /// <summary>
        /// Creates the JWT payload
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The JWT payload</returns>
        protected virtual Task<JwtPayload> CreatePayloadAsync(Token token)
        {
            var payload = new JwtPayload(
                token.Issuer,
                token.Audience,
                null,
                DateTime.UtcNow,
                DateTime.UtcNow.AddSeconds(token.Lifetime));

            var amrClaims = token.Claims.Where(x => x.Type == JwtClaimTypes.AuthenticationMethod);
            var jsonClaims = token.Claims.Where(x => x.ValueType == Constants.ClaimValueTypes.Json);
            var normalClaims = token.Claims.Except(amrClaims).Except(jsonClaims);

            payload.AddClaims(normalClaims);

            // deal with amr
            var amrValues = amrClaims.Select(x => x.Value).Distinct().ToArray();
            if (amrValues.Any())
            {
                payload.Add(JwtClaimTypes.AuthenticationMethod, amrValues);
            }

            // deal with json types
            // calling ToArray() to trigger JSON parsing once and so later 
            // collection identity comparisons work for the anonymous type
            var jsonTokens = jsonClaims.Select(x => new { x.Type, JsonValue = JRaw.Parse(x.Value) }).ToArray();

            var jsonObjects = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Object).ToArray();
            var jsonObjectGroups = jsonObjects.GroupBy(x => x.Type).ToArray();
            foreach (var group in jsonObjectGroups)
            {
                if (payload.ContainsKey(group.Key))
                {
                    throw new Exception($"Can't add two claims where one is a JSON object and the other is not a JSON object ({@group.Key})");
                }

                if (group.Skip(1).Any())
                {
                    // add as array
                    payload.Add(group.Key, group.Select(x => x.JsonValue).ToArray());
                }
                else
                {
                    // add just one
                    payload.Add(group.Key, group.First().JsonValue);
                }
            }

            var jsonArrays = jsonTokens.Where(x => x.JsonValue.Type == JTokenType.Array).ToArray();
            var jsonArrayGroups = jsonArrays.GroupBy(x => x.Type).ToArray();
            foreach (var group in jsonArrayGroups)
            {
                if (payload.ContainsKey(group.Key))
                {
                    throw new Exception($"Can't add two claims where one is a JSON array and the other is not a JSON array ({@group.Key})");
                }

                List<JToken> newArr = new List<JToken>();
                foreach (var arrays in group)
                {
                    var arr = (JArray)arrays.JsonValue;
                    newArr.AddRange(arr);
                }

                // add just one array for the group/key/claim type
                payload.Add(group.Key, newArr.ToArray());
            }

            var unsupportedJsonTokens = jsonTokens.Except(jsonObjects).Except(jsonArrays);
            var unsupportedJsonClaimTypes = unsupportedJsonTokens.Select(x => x.Type).Distinct();
            if (unsupportedJsonClaimTypes.Any())
            {
                throw new Exception($"Unsupported JSON type for claim types: {unsupportedJsonClaimTypes.Aggregate((x, y) => x + ", " + y)}");
            }

            return Task.FromResult(payload);
        }

        /// <summary>
        /// Applies the signature to the JWT
        /// </summary>
        /// <param name="jwt">The JWT object.</param>
        /// <returns>The signed JWT</returns>
        protected virtual async Task<string> SignAsync(JwtSecurityToken jwt)
        {
            var rawDataBytes = System.Text.Encoding.UTF8.GetBytes(jwt.EncodedHeader + "." + jwt.EncodedPayload); // TODO: Is UTF-8 correct?

            var keyVaultSignatureProvider = new AzureKeyVaultSignatureProvider(_options.KeyIdentifier, JsonWebKeySignatureAlgorithm.RS256, _authentication.KeyVaultClientAuthenticationCallback);

            var rawSignature = await Task.Run(() => Convert.ToBase64String(keyVaultSignatureProvider.Sign(rawDataBytes))).ConfigureAwait(false);

            return jwt.EncodedHeader + "." + jwt.EncodedPayload + "." + rawSignature;

            //var handler = new JwtSecurityTokenHandler
            //{
            //    SignatureProviderFactory = new AzureKeyVaultSignatureProviderFactory()
            //};
            //return Task.FromResult(handler.WriteToken(jwt));
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }
}
