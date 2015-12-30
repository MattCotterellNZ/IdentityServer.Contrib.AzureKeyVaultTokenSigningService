namespace IdentityServer3.Contrib.AzureKeyVaultTokenSigningService
{
    public class AzureKeyVaultTokenSigningServiceOptions
    {
        public string KeyIdentifier { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }
}