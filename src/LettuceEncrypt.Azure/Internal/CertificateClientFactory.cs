// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal;

internal interface ICertificateClientFactory
{
    CertificateClient Create();
}

internal class CertificateClientFactory : ICertificateClientFactory
{
    private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;

    public CertificateClientFactory(IOptions<AzureKeyVaultLettuceEncryptOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public CertificateClient Create()
    {
        var value = _options.Value;

        if (string.IsNullOrEmpty(value.AzureKeyVaultEndpoint))
        {
            throw new ArgumentException("Missing required option: AzureKeyVaultEndpoint");
        }

        var vaultUri = new Uri(value.AzureKeyVaultEndpoint);
        var credentials = value.Credentials ?? new DefaultAzureCredential();

        return new CertificateClient(vaultUri, credentials);
    }
}
