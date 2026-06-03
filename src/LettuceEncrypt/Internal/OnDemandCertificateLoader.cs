// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

/// <summary>
/// Retrieves certificates from the registered certificate sources on demand, at TLS-handshake time,
/// when the runtime certificate store has no certificate for the requested domain.
/// </summary>
internal interface IOnDemandCertificateLoader
{
    /// <summary>
    /// Attempts to retrieve a certificate for <paramref name="domainName"/> from the registered
    /// certificate sources. Returns <c>null</c> when on-demand lookup is disabled, the domain is not
    /// part of the configured domain set, a recent lookup for the domain found nothing (cooldown),
    /// or no matching certificate was found. Never throws.
    /// </summary>
    Task<X509Certificate2?> TryRetrieveAsync(string domainName, CancellationToken cancellationToken = default);
}

internal class OnDemandCertificateLoader : IOnDemandCertificateLoader
{
    private readonly IEnumerable<ICertificateSource> _certSources;
    private readonly IDomainLoader _domainLoader;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly IClock _clock;
    private readonly ILogger<OnDemandCertificateLoader> _logger;

    // Single-flight: concurrent handshakes for the same domain await the same lookup task.
    private readonly ConcurrentDictionary<string, Lazy<Task<X509Certificate2?>>> _inFlight =
        new(StringComparer.OrdinalIgnoreCase);

    // Negative cache: last time a lookup for a domain failed to find a certificate.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _negativeCache =
        new(StringComparer.OrdinalIgnoreCase);

    public OnDemandCertificateLoader(
        IEnumerable<ICertificateSource> certSources,
        IDomainLoader domainLoader,
        IOptions<LettuceEncryptOptions> options,
        IClock clock,
        ILogger<OnDemandCertificateLoader> logger)
    {
        _certSources = certSources ?? throw new ArgumentNullException(nameof(certSources));
        _domainLoader = domainLoader ?? throw new ArgumentNullException(nameof(domainLoader));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<X509Certificate2?> TryRetrieveAsync(string domainName, CancellationToken cancellationToken = default)
    {
        try
        {
            if (!_options.Value.EnableOnDemandCertificateLookup)
            {
                return null;
            }

            if (!await IsDomainAllowedAsync(domainName, cancellationToken))
            {
                // Not a configured domain (e.g. scanner SNI) - never touch sources or the negative cache.
                _logger.LogTrace(
                    "Skipping on-demand certificate lookup for {domainName} because it is not a configured domain",
                    domainName);
                return null;
            }

            if (_negativeCache.TryGetValue(domainName, out var lastAttempt) &&
                _clock.Now - lastAttempt < _options.Value.OnDemandLookupCooldown)
            {
                return null;
            }

            var lazyLookup = _inFlight.GetOrAdd(
                domainName,
                domain => new Lazy<Task<X509Certificate2?>>(
                    () => QuerySourcesAsync(domain, cancellationToken),
                    LazyThreadSafetyMode.ExecutionAndPublication));

            try
            {
                return await lazyLookup.Value;
            }
            finally
            {
                // Remove only our own entry so failures are never cached permanently;
                // throttling is handled exclusively by the negative-cache cooldown.
                _inFlight.TryRemove(KeyValuePair.Create(domainName, lazyLookup));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "On-demand certificate lookup for {domainName} failed", domainName);
            return null;
        }
    }

    // internal for testing
    internal async Task<bool> IsDomainAllowedAsync(string domainName, CancellationToken cancellationToken)
    {
        var domainCerts = await _domainLoader.GetDomainCertsAsync(cancellationToken);
        foreach (var domainCert in domainCerts)
        {
            foreach (var domain in domainCert.Domains)
            {
                if (Matches(domain, domainName))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private async Task<X509Certificate2?> QuerySourcesAsync(string domainName, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Attempting on-demand certificate lookup for {domainName}", domainName);

        X509Certificate2? bestCert = null;
        foreach (var certSource in _certSources)
        {
            X509Certificate2? cert;
            try
            {
                cert = await certSource.GetCertificateAsync(domainName, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to load certificate from source {certSource} during on-demand lookup for {domainName}",
                    certSource.GetType().Name, domainName);
                continue;
            }

            if (cert == null)
            {
                continue;
            }

            // Sources are not guaranteed to filter, so defensively skip expired or key-less
            // certificates and certificates that do not actually cover the requested domain.
            if (!cert.HasPrivateKey || cert.NotAfter <= _clock.Now.LocalDateTime)
            {
                continue;
            }

            if (!X509CertificateHelpers.GetAllDnsNames(cert).Contains(domainName, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            // Prefer the certificate with the longest TTL, mirroring the runtime store semantics.
            if (bestCert == null || cert.NotAfter >= bestCert.NotAfter)
            {
                bestCert = cert;
            }
        }

        if (bestCert == null)
        {
            _negativeCache[domainName] = _clock.Now;
            _logger.LogDebug("On-demand certificate lookup for {domainName} found no certificate", domainName);
        }
        else
        {
            _negativeCache.TryRemove(domainName, out _);
            _logger.LogInformation(
                "On-demand certificate lookup found certificate {thumbprint} for {domainName}",
                bestCert.Thumbprint, domainName);
        }

        return bestCert;
    }

    private static bool Matches(string pattern, string host)
    {
        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            // "*.example.com" matches "foo.example.com" but not "example.com" or "a.b.example.com"
            var suffix = pattern[1..]; // ".example.com"
            if (host.Length <= suffix.Length || !host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var leftLabel = host.AsSpan(0, host.Length - suffix.Length);
            return leftLabel.IndexOf('.') < 0;
        }

        return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
    }
}
