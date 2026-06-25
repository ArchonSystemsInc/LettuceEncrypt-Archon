// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certify.ACME.Anvil;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class AcmeClientFactory
{
    private readonly ICertificateAuthorityConfiguration _certificateAuthority;
    private readonly ILogger<AcmeClient> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;

    public AcmeClientFactory(
        ICertificateAuthorityConfiguration certificateAuthority,
        ILogger<AcmeClient> logger,
        IOptions<LettuceEncryptOptions> options)
    {
        _certificateAuthority = certificateAuthority;
        _logger = logger;
        _options = options;
    }

    public AcmeClient Create(IKey acmeAccountKey)
    {
        var directoryUri = _certificateAuthority.AcmeDirectoryUri;

        return new AcmeClient(_logger, _options, directoryUri, acmeAccountKey);
    }
}
