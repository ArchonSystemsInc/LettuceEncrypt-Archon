// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using LettuceEncrypt.Azure.Internal;
using LettuceEncrypt.UnitTests;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.Azure.UnitTests;

public class AzureKeyVaultTests
{
    private static void DefaultConfigure(AzureKeyVaultLettuceEncryptOptions options)
    {
        options.AzureKeyVaultEndpoint = "http://something";
    }

    [Fact]
    public void SourceAndRepositorySameInstance()
    {
        var provider = new ServiceCollection()
            .AddSingleton<IHostEnvironment, HostingEnvironment>()
            .AddLogging()
            .AddLettuceEncrypt()
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .Services
            .BuildServiceProvider(validateScopes: true);


        var repository = provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>()
            .First();
        var source = provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>()
            .First();

        Assert.Same(source, repository);
    }

    [Fact]
    public void MultipleCallsToPersistCertificatesToAzureKeyVaultDoesNotDuplicateServices()
    {
        var provider = new ServiceCollection()
            .AddSingleton<IHostEnvironment, HostingEnvironment>()
            .AddLogging()
            .AddLettuceEncrypt()
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .PersistCertificatesToAzureKeyVault(DefaultConfigure)
            .Services
            .BuildServiceProvider(validateScopes: true);


        Assert.Single(provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>());
        Assert.Single(provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>());
    }

    [Fact]
    public async Task ImportCertificateChecksDuplicate()
    {
        const string Domain1 = "github.com";
        const string Domain2 = "azure.com";

        var certClient = new Mock<CertificateClient>();
        var certClientFactory = new Mock<ICertificateClientFactory>();
        certClientFactory.Setup(c => c.Create()).Returns(certClient.Object);
        var options = Options.Create(new LettuceEncryptOptions());

        options.Value.DomainNames = new[] { Domain1, Domain2 };

        var repository = new AzureKeyVaultCertificateRepository(
            certClientFactory.Object,
            Mock.Of<ISecretClientFactory>(),
            Mock.Of<IDomainLoader>(),
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);
        foreach (var domain in options.Value.DomainNames)
        {
            var certificateToSave = TestUtils.CreateTestCert(domain);
            await repository.SaveAsync(certificateToSave, CancellationToken.None);
        }

        certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
            CancellationToken.None));
        certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
            CancellationToken.None));
    }

    [Fact]
    public async Task GetCertificateLooksForDomainsAsync()
    {
        const string Domain1 = "github.com";
        const string Domain2 = "azure.com";

        var domainLoader = new Mock<IDomainLoader>();
        domainLoader.Setup(x => x.GetDomainCertsAsync(default, false))
            .Returns(() => Task.FromResult(
                new[] { new SingleDomainCert { Domain = Domain1 }, new SingleDomainCert { Domain = Domain2 } }.AsEnumerable<IDomainCert>()
            ));

        var secretClient = new Mock<SecretClient>();
        var secretClientFactory = new Mock<ISecretClientFactory>();
        secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);
        var options = Options.Create(new LettuceEncryptOptions());

        options.Value.DomainNames = new[] { Domain1, Domain2 };

        var repository = new AzureKeyVaultCertificateRepository(
            Mock.Of<ICertificateClientFactory>(),
            secretClientFactory.Object, domainLoader.Object,
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

        Assert.Empty(certificates);

        secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
            null, CancellationToken.None));
        secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
            null, CancellationToken.None));
    }

    [Fact]
    public async Task DomainSpecificLookupFetchesByGroupFirstDomain()
    {
        const string PrimaryDomain = "github.com";
        const string SecondaryDomain = "azure.com";

        var domainLoader = new Mock<IDomainLoader>();
        domainLoader.Setup(x => x.GetDomainCertsAsync(It.IsAny<CancellationToken>(), false))
            .Returns(() => Task.FromResult(new IDomainCert[]
            {
                new MultipleDomainCert { OrderedDomains = new HashSet<string> { PrimaryDomain, SecondaryDomain } }
            }.AsEnumerable()));

        var testCert = TestUtils.CreateTestCert(new[] { PrimaryDomain, SecondaryDomain });
        var secretName = AzureKeyVaultCertificateRepository.NormalizeHostName(PrimaryDomain);
        var secretValue = Convert.ToBase64String(testCert.Export(X509ContentType.Pfx));

        var secretClient = new Mock<SecretClient>();
        secretClient
            .Setup(c => c.GetSecretAsync(secretName, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(new KeyVaultSecret(secretName, secretValue), null));
        var secretClientFactory = new Mock<ISecretClientFactory>();
        secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);

        var repository = new AzureKeyVaultCertificateRepository(
            Mock.Of<ICertificateClientFactory>(),
            secretClientFactory.Object,
            domainLoader.Object,
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        // Requesting the secondary domain must resolve to the group's first domain for the lookup.
        var cert = await repository.GetCertificateAsync(SecondaryDomain, CancellationToken.None);

        Assert.NotNull(cert);
        Assert.Equal(testCert.Thumbprint, cert!.Thumbprint);
        secretClient.Verify(c => c.GetSecretAsync(secretName, null, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DomainSpecificLookupReturnsNullForUnknownDomain()
    {
        var domainLoader = new Mock<IDomainLoader>();
        domainLoader.Setup(x => x.GetDomainCertsAsync(It.IsAny<CancellationToken>(), false))
            .Returns(() => Task.FromResult(new IDomainCert[]
            {
                new SingleDomainCert { Domain = "github.com" }
            }.AsEnumerable()));

        var secretClient = new Mock<SecretClient>();
        var secretClientFactory = new Mock<ISecretClientFactory>();
        secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);

        var repository = new AzureKeyVaultCertificateRepository(
            Mock.Of<ICertificateClientFactory>(),
            secretClientFactory.Object,
            domainLoader.Object,
            NullLogger<AzureKeyVaultCertificateRepository>.Instance);

        var cert = await repository.GetCertificateAsync("unknown.test", CancellationToken.None);

        Assert.Null(cert);
        secretClient.Verify(
            c => c.GetSecretAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
