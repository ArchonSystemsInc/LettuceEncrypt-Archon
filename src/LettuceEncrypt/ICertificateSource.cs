// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt;

/// <summary>
/// Defines a source for certificates.
/// </summary>
public interface ICertificateSource
{
    /// <summary>
    /// Gets available certificates from the source.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A collection of certificates.</returns>
    Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets a certificate for the specified domain, or <c>null</c> if the source has none.
    /// <para>
    /// Used for on-demand certificate lookups at TLS-handshake time (see
    /// <see cref="LettuceEncryptOptions.EnableOnDemandCertificateLookup"/>) so sources can avoid
    /// fetching all certificates when only a single domain is needed.
    /// </para>
    /// </summary>
    /// <param name="domainName">The domain name to find a certificate for.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A certificate valid for <paramref name="domainName"/>, or <c>null</c>.</returns>
    Task<X509Certificate2?> GetCertificateAsync(string domainName, CancellationToken cancellationToken);
}
