using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;

namespace IdentityServer.Contrib.AzureKeyVaultTokenSigningService
{
    // This project can output the Class library as a NuGet Package.
    // To enable this option, right-click on the project and select the Properties menu item. In the Build tab select "Produce outputs on build".
    public class AzureKeyVaultTokenSigningService : ITokenSigningService
    {
        public AzureKeyVaultTokenSigningService()
        {
        }

        Task<string> ITokenSigningService.SignTokenAsync(Token token)
        {
            throw new NotImplementedException();
        }
    }
}
