// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class CertificateSelector : IServerCertificateSelector
{
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly ILogger<CertificateSelector> _logger;
    private readonly IRuntimeCertificateStore _runtimeCertificateStore;
    private readonly IOnDemandCertificateLoader _onDemandCertificateLoader;

    public CertificateSelector(IOptions<LettuceEncryptOptions> options, ILogger<CertificateSelector> logger, IRuntimeCertificateStore runtimeCertificateStore, IOnDemandCertificateLoader onDemandCertificateLoader)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _runtimeCertificateStore = runtimeCertificateStore;
        _onDemandCertificateLoader = onDemandCertificateLoader ?? throw new ArgumentNullException(nameof(onDemandCertificateLoader));
    }

    public IEnumerable<string> SupportedDomains => _runtimeCertificateStore.GetAllCertDomainsAsync().Result;

    public virtual async Task AddAsync(X509Certificate2 certificate)
    {
        var preloaded = false;
        foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
        {
            var selectedCert = await _runtimeCertificateStore.AddCertWithDomainNameAsync(dnsName, certificate);

            // Call preload once per certificate, but only if the certificate is actually selected to be used
            // for this domain. This is a small optimization which avoids preloading on a cert that may not be used.
            if (!preloaded && selectedCert.Equals(certificate))
            {
                preloaded = true;
                PreloadIntermediateCertificates(selectedCert);
            }
        }
    }

    public virtual async Task AddChallengeCertAsync(X509Certificate2 certificate)
    {
        foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
        {
            await _runtimeCertificateStore.AddChallengeCertWithDomainNameAsync(dnsName, certificate);
        }
    }

    public async Task ClearChallengeCertAsync(string dnsName)
    {
        await _runtimeCertificateStore.RemoveChallengeCertAsync(dnsName);
    }

    public async Task<bool> HasCertForDomainAsync(IDomainCert domainCert)
    {
        foreach (var domainName in domainCert.Domains)
        {
            if (!await _runtimeCertificateStore.ContainsCertForDomainAsync(domainName))
            {
                return false;
            }
        }

        return true;
    }

    public X509Certificate2? Select(ConnectionContext? context, string? domainName)
    {
        return SelectAsync(context, domainName).Result;
    }

    public async Task<X509Certificate2?> SelectAsync(ConnectionContext? context, string? domainName)
    {
        if (await _runtimeCertificateStore.AnyChallengeCertAsync())
        {
            // var sslStream = context.Features.Get<SslStream>();
            // sslStream.NegotiatedApplicationProtocol hasn't been set yet, so we have to assume that
            // if ALPN challenge certs are configured, we must respond with those.

            if (domainName != null)
            {
                var challengeCert = await _runtimeCertificateStore.GetChallengeCertAsync(domainName);
                if (challengeCert != null)
                {
                    _logger.LogTrace("Using ALPN challenge cert for {domainName}", domainName);

                    return challengeCert;
                }
            }
        }

        if (domainName == null)
        {
            return _options.Value.FallbackCertificate;
        }

        var cert = await _runtimeCertificateStore.GetCertAsync(domainName);
        if (cert != null)
        {
            return cert;
        }

        // Fall back to retrieving the certificate from the underlying certificate sources on demand.
        var onDemandCert = await _onDemandCertificateLoader.TryRetrieveAsync(domainName);
        if (onDemandCert != null)
        {
            // Populate the runtime store so subsequent connections are served from memory.
            await AddAsync(onDemandCert);
            return await _runtimeCertificateStore.GetCertAsync(domainName) ?? onDemandCert;
        }

        return _options.Value.FallbackCertificate;
    }

    public async Task ResetAsync(string domainName)
    {
        await _runtimeCertificateStore.RemoveCertAsync(domainName);
    }

    public Task<X509Certificate2?> TryGetAsync(string domainName)
    {
        return _runtimeCertificateStore.GetCertAsync(domainName);
    }

    private void PreloadIntermediateCertificates(X509Certificate2 certificate)
    {
        if (certificate.IsSelfSigned())
        {
            return;
        }

        // workaround for https://github.com/dotnet/aspnetcore/issues/21183
        using var chain = new X509Chain
        {
            ChainPolicy =
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };

        var commonName = X509CertificateHelpers.GetCommonName(certificate);
        try
        {
            if (chain.Build(certificate))
            {
                _logger.LogTrace("Successfully tested certificate chain for {commonName}", commonName);
                return;
            }
        }
        catch (CryptographicException ex)
        {
            _logger.LogDebug(ex, "Failed to validate certificate chain for {commonName}", commonName);
        }

        _logger.LogWarning(
            "Failed to validate certificate for {commonName} ({thumbprint}). This could cause an outage of your app.",
            commonName, certificate.Thumbprint);
    }
}
