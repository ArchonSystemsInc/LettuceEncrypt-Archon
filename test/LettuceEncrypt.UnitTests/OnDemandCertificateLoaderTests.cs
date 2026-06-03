// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

using static TestUtils;

public class OnDemandCertificateLoaderTests
{
    [Fact]
    public async Task RetrievesCertFromSourceForConfiguredDomain()
    {
        const string DomainName = "a.test";
        var testCert = CreateTestCert(DomainName);
        var source = CreateSource(testCert);

        var loader = CreateLoader(new LettuceEncryptOptions(), new TestClock(), new[] { DomainName }, source.Object);

        var result = await loader.TryRetrieveAsync(DomainName);

        Assert.NotNull(result);
        Assert.Equal(testCert.Thumbprint, result.Thumbprint);
    }

    [Fact]
    public async Task UsesPerDomainLookupInsteadOfEnumeration()
    {
        const string DomainName = "a.test";
        var source = CreateSource(CreateTestCert(DomainName));

        var loader = CreateLoader(new LettuceEncryptOptions(), new TestClock(), new[] { DomainName }, source.Object);

        Assert.NotNull(await loader.TryRetrieveAsync(DomainName));
        source.Verify(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()), Times.Once);
        source.Verify(s => s.GetCertificatesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ReturnsNullForDomainNotInConfiguredSet()
    {
        var source = CreateSource(CreateTestCert("b.test"));

        var loader = CreateLoader(new LettuceEncryptOptions(), new TestClock(), new[] { "a.test" }, source.Object);

        Assert.Null(await loader.TryRetrieveAsync("b.test"));
        source.Verify(
            s => s.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Theory]
    [InlineData("a.example.com", true)]
    [InlineData("A.EXAMPLE.COM", true)]
    [InlineData("example.com", false)]
    [InlineData("a.b.example.com", false)]
    [InlineData("aexample.com", false)]
    public async Task WildcardDomainMatching(string host, bool expected)
    {
        var loader = CreateLoader(new LettuceEncryptOptions(), new TestClock(), new[] { "*.example.com" });

        Assert.Equal(expected, await loader.IsDomainAllowedAsync(host, default));
    }

    [Fact]
    public async Task NegativeCacheSuppressesLookupWithinCooldown()
    {
        const string DomainName = "a.test";
        var clock = new TestClock();
        var source = CreateSource(); // no certs -> every lookup misses
        var options = new LettuceEncryptOptions { OnDemandLookupCooldown = TimeSpan.FromMinutes(5) };

        var loader = CreateLoader(options, clock, new[] { DomainName }, source.Object);

        Assert.Null(await loader.TryRetrieveAsync(DomainName));
        Assert.Null(await loader.TryRetrieveAsync(DomainName));
        source.Verify(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()), Times.Once);

        clock.Now += TimeSpan.FromMinutes(6);

        Assert.Null(await loader.TryRetrieveAsync(DomainName));
        source.Verify(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task SuccessClearsNegativeCache()
    {
        const string DomainName = "a.test";
        var clock = new TestClock();
        var certs = new List<X509Certificate2>();
        var source = new Mock<ICertificateSource>();
        source
            .Setup(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => certs.FirstOrDefault());
        var options = new LettuceEncryptOptions { OnDemandLookupCooldown = TimeSpan.FromMinutes(5) };

        var loader = CreateLoader(options, clock, new[] { DomainName }, source.Object);

        // miss -> negative cached
        Assert.Null(await loader.TryRetrieveAsync(DomainName));

        // cert appears, but within the cooldown the lookup is still suppressed
        certs.Add(CreateTestCert(DomainName));
        Assert.Null(await loader.TryRetrieveAsync(DomainName));

        clock.Now += TimeSpan.FromMinutes(6);
        Assert.NotNull(await loader.TryRetrieveAsync(DomainName));

        // success cleared the negative cache: an immediate retry queries the source again
        Assert.NotNull(await loader.TryRetrieveAsync(DomainName));
        source.Verify(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()), Times.Exactly(3));
    }

    [Fact]
    public async Task SingleFlightCollapsesConcurrentLookups()
    {
        const string DomainName = "a.test";
        var testCert = CreateTestCert(DomainName);
        var gate = new TaskCompletionSource();
        var callCount = 0;
        var source = new Mock<ICertificateSource>();
        source
            .Setup(s => s.GetCertificateAsync(DomainName, It.IsAny<CancellationToken>()))
            .Returns(async (string _, CancellationToken _) =>
            {
                Interlocked.Increment(ref callCount);
                await gate.Task;
                return testCert;
            });

        var loader = CreateLoader(new LettuceEncryptOptions(), new TestClock(), new[] { DomainName }, source.Object);

        var tasks = Enumerable.Range(0, 10)
            .Select(_ => loader.TryRetrieveAsync(DomainName))
            .ToArray();

        gate.SetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, callCount);
        Assert.All(results, r => Assert.NotNull(r));
    }

    [Fact]
    public async Task ThrowingSourceIsSwallowedAndOtherSourcesQueried()
    {
        const string DomainName = "a.test";
        var testCert = CreateTestCert(DomainName);
        var throwingSource = new Mock<ICertificateSource>();
        throwingSource
            .Setup(s => s.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("store is down"));
        var goodSource = CreateSource(testCert);

        var loader = CreateLoader(
            new LettuceEncryptOptions(), new TestClock(), new[] { DomainName },
            throwingSource.Object, goodSource.Object);

        var result = await loader.TryRetrieveAsync(DomainName);

        Assert.NotNull(result);
        Assert.Equal(testCert.Thumbprint, result.Thumbprint);
    }

    [Fact]
    public async Task FiltersExpiredAndKeylessCerts()
    {
        const string DomainName = "a.test";
        var expiredCert = CreateTestCert(DomainName, DateTimeOffset.Now.AddSeconds(-30));
        var keylessCert = X509CertificateLoader.LoadCertificate(
            CreateTestCert(DomainName).Export(X509ContentType.Cert));
        var validCert = CreateTestCert(DomainName);

        var loader = CreateLoader(
            new LettuceEncryptOptions(), new TestClock(), new[] { DomainName },
            CreateSource(expiredCert).Object, CreateSource(keylessCert).Object, CreateSource(validCert).Object);

        var result = await loader.TryRetrieveAsync(DomainName);

        Assert.NotNull(result);
        Assert.Equal(validCert.Thumbprint, result.Thumbprint);

        // sources with only unusable certs yield null
        var loader2 = CreateLoader(
            new LettuceEncryptOptions(), new TestClock(), new[] { DomainName },
            CreateSource(expiredCert).Object, CreateSource(keylessCert).Object);

        Assert.Null(await loader2.TryRetrieveAsync(DomainName));
    }

    [Fact]
    public async Task OptOutDisablesLookup()
    {
        const string DomainName = "a.test";
        var source = CreateSource(CreateTestCert(DomainName));
        var options = new LettuceEncryptOptions { EnableOnDemandCertificateLookup = false };

        var loader = CreateLoader(options, new TestClock(), new[] { DomainName }, source.Object);

        Assert.Null(await loader.TryRetrieveAsync(DomainName));
        source.Verify(
            s => s.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static OnDemandCertificateLoader CreateLoader(
        LettuceEncryptOptions options,
        TestClock clock,
        string[] allowedDomains,
        params ICertificateSource[] sources)
    {
        return new OnDemandCertificateLoader(
            sources,
            CreateDomainLoader(allowedDomains),
            Options.Create(options),
            clock,
            NullLogger<OnDemandCertificateLoader>.Instance);
    }

    private static IDomainLoader CreateDomainLoader(string[] domains)
    {
        var domainCerts = domains.Length == 0
            ? Array.Empty<IDomainCert>()
            : new IDomainCert[] { new MultipleDomainCert { OrderedDomains = new HashSet<string>(domains) } };

        var mock = new Mock<IDomainLoader>();
        mock
            .Setup(d => d.GetDomainCertsAsync(It.IsAny<CancellationToken>(), It.IsAny<bool>()))
            .ReturnsAsync(domainCerts);
        return mock.Object;
    }

    private static Mock<ICertificateSource> CreateSource(params X509Certificate2[] certs)
    {
        var source = new Mock<ICertificateSource>();
        source
            .Setup(s => s.GetCertificatesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(certs);
        source
            .Setup(s => s.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string domain, CancellationToken _) => certs.FirstOrDefault(
                c => X509CertificateHelpers.GetAllDnsNames(c).Contains(domain, StringComparer.OrdinalIgnoreCase)));
        return source;
    }
}
