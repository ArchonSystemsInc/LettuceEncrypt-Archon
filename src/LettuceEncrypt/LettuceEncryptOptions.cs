// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Acme;

namespace LettuceEncrypt;

/// <summary>
/// Options for configuring an ACME server to automatically generate HTTPS certificates.
/// </summary>
public class LettuceEncryptOptions
{
    private string[] _domainNames = Array.Empty<string>();
    private bool? _useStagingServer;

    /// <summary>
    /// The domain names for which to generate certificates.
    /// </summary>
    public string[] DomainNames
    {
        get => _domainNames;
        set => _domainNames = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Indicate that you agree with ACME server's terms of service.
    /// </summary>
    public bool AcceptTermsOfService { get; set; }

    /// <summary>
    /// The email address used to register with the certificate authority.
    /// </summary>
    public string EmailAddress { get; set; } = string.Empty;

    /// <summary>
    /// Use Let's Encrypt staging server.
    /// <para>
    /// This is recommended during development of the application and is automatically enabled
    /// if the hosting environment name is 'Development'.
    /// </para>
    /// </summary>
    public bool UseStagingServer
    {
        get => _useStagingServer ?? false;
        set => _useStagingServer = value;
    }

    internal bool UseStagingServerExplicitlySet => _useStagingServer.HasValue;

    /// <summary>
    /// Additional issuers passed to the ACME library before building the successfully downloaded certificate,
    /// used internally to verify the issuer for authenticity.
    /// <para>
    /// This is useful especially when using a staging server (e.g. for integration tests) with a root certificate
    /// that is not part of the ACME library's embedded resources.
    /// </para>
    /// </summary>
    /// <remarks>
    /// LettuceEncrypt uses Certify.ACME.Anvil internally, which depends on BouncyCastle.Cryptography to parse
    /// certificates. See https://github.com/bcgit/bc-csharp/blob/830d9b8c7bdfcec511bff0a6cf4a0e8ed568e7c1/crypto/src/x509/X509CertificateParser.cs#L20
    /// if you're wondering what certificate formats are supported.
    /// </remarks>
    public string[] AdditionalIssuers { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Optional preferred certificate chain. When set, LettuceEncrypt selects the offered chain
    /// (default or alternate) whose trust anchor matches this value (e.g. <c>"ISRG Root X1"</c>);
    /// if no chain matches, the server's default chain is used. Matched against the issuer Common
    /// Name of the topmost (root-most) certificate of each offered chain — the same rule Certbot's
    /// <c>--preferred-chain</c> uses.
    /// <para>
    /// Leave <c>null</c> (the default) to accept whatever chain the ACME server returns.
    /// </para>
    /// </summary>
    public string? PreferredChain { get; set; }

    /// <summary>
    /// A certificate to use if a certificates cannot be created automatically.
    /// <para>
    /// This can be null if there is not fallback certificate.
    /// </para>
    /// </summary>
    public X509Certificate2? FallbackCertificate { get; set; }

    /// <summary>
    /// When <c>true</c>, a TLS handshake for a domain that has no certificate loaded in memory will
    /// trigger an on-demand lookup against all registered certificate sources before falling back to
    /// <see cref="FallbackCertificate"/>. Only domains that are part of the configured domain set
    /// (see <see cref="DomainNames"/>) can trigger a lookup.
    /// </summary>
    public bool EnableOnDemandCertificateLookup { get; set; } = true;

    /// <summary>
    /// How long to suppress repeated on-demand certificate lookups for a domain after a lookup fails
    /// to find a certificate. This prevents repeated certificate source queries for domains that have
    /// no certificate. Only used when <see cref="EnableOnDemandCertificateLookup"/> is enabled.
    /// </summary>
    public TimeSpan OnDemandLookupCooldown { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How long before certificate expiration will be renewal attempted.
    /// Set to <c>null</c> to disable automatic renewal.
    /// </summary>
    public TimeSpan? RenewDaysInAdvance { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// How often will be certificates checked for renewal
    /// </summary>
    public TimeSpan? RenewalCheckPeriod { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// How long to wait between failed cert creation/renewal attempts
    /// </summary>
    public TimeSpan FailedRenewalBackoffPeriod { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The asymmetric algorithm used for generating a private key for certificates: RS256, ES256, ES384, ES512
    /// </summary>
    public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.ES256;

    /// <summary>
    /// The key size used for generating a private key for certificates
    /// </summary>
    public int? KeySize { get; set; }

    /// <summary>
    /// Specifies which kinds of ACME challenges LettuceEncrypt can use to verify domain ownership.
    /// Defaults to <see cref="ChallengeType.Any"/>.
    /// </summary>
    public ChallengeType AllowedChallengeTypes { get; set; } = ChallengeType.Any;

    /// <summary>
    /// Optional EAB (External Account Binding) account credentials used for creating new account.
    /// </summary>
    public EabCredentials EabCredentials { get; set; } = new();
}
