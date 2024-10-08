// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class DefaultCertificateAuthorityConfiguration : ICertificateAuthorityConfiguration
{
    private readonly IHostEnvironment _env;
    private readonly IOptions<LettuceEncryptOptions> _options;

    public DefaultCertificateAuthorityConfiguration(IHostEnvironment env, IOptions<LettuceEncryptOptions> options)
    {
        _env = env ?? throw new ArgumentNullException(nameof(env));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public Uri AcmeDirectoryUri
    {
        get
        {
            var options = _options.Value;
            var useStaging = options.UseStagingServerExplicitlySet
                ? options.UseStagingServer
                : _env.IsDevelopment();

            return useStaging
                ? WellKnownServers.LetsEncryptStagingV2
                : WellKnownServers.LetsEncryptV2;
        }
    }
}
