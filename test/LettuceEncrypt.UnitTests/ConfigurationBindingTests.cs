// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.Tests;

public class ConfigurationBindingTests
{
    [Fact]
    public void ItBindsToConfig()
    {
        var options = ParseOptions(new()
        {
            ["LettuceEncrypt:AcceptTermsOfService"] = "true",
            ["LettuceEncrypt:DomainNames:0"] = "one.com",
            ["LettuceEncrypt:DomainNames:1"] = "two.com",
            ["LettuceEncrypt:AllowedChallengeTypes"] = "Http01",
            ["LettuceEncrypt:PreferredChain"] = "ISRG Root X1",
            ["LettuceEncrypt:FinalizeOrderRetryCount"] = "7",
        });

        Assert.True(options.AcceptTermsOfService);
        Assert.Collection(options.DomainNames,
            one => Assert.Equal("one.com", one),
            two => Assert.Equal("two.com", two));
        Assert.Equal(Acme.ChallengeType.Http01, options.AllowedChallengeTypes);
        Assert.Equal("ISRG Root X1", options.PreferredChain);
        Assert.Equal(7, options.FinalizeOrderRetryCount);
    }

    [Fact]
    public void PreferredChainDefaultsToNull()
    {
        var options = ParseOptions(new());

        Assert.Null(options.PreferredChain);
    }

    [Fact]
    public void FinalizeOrderRetryCountDefaultsToFive()
    {
        var options = ParseOptions(new());

        Assert.Equal(5, options.FinalizeOrderRetryCount);
    }

    [Fact]
    public void ExplicitOptionsWin()
    {
        var data = new Dictionary<string, string>
        {
            ["LettuceEncrypt:EmailAddress"] = "config",
        };
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(data)
            .Build();

        var services = new ServiceCollection()
            .AddSingleton<IConfiguration>(config)
            .AddLettuceEncrypt(o => { o.EmailAddress = "code"; })
            .Services
            .BuildServiceProvider(true);

        var options = services.GetRequiredService<IOptions<LettuceEncryptOptions>>();

        Assert.Equal("code", options.Value.EmailAddress);
    }

    [Theory]
    [InlineData("http01", Acme.ChallengeType.Http01)]
    [InlineData("HTTP01", Acme.ChallengeType.Http01)]
    [InlineData("Any", Acme.ChallengeType.Any)]
    [InlineData("TlsAlpn01, http01", Acme.ChallengeType.TlsAlpn01 | Acme.ChallengeType.Http01)]
    public void ItParsesEnumValuesForChallengeType(string value, Acme.ChallengeType challengeType)
    {
        var options = ParseOptions(new()
        {
            ["LettuceEncrypt:AllowedChallengeTypes"] = value,
        });

        Assert.Equal(challengeType, options.AllowedChallengeTypes);
    }

    private static LettuceEncryptOptions ParseOptions(Dictionary<string, string> input)
    {
        var config = new ConfigurationBuilder()
                   .AddInMemoryCollection(input)
                   .Build();

        var services = new ServiceCollection()
            .AddSingleton<IConfiguration>(config)
            .AddLettuceEncrypt()
            .Services
            .BuildServiceProvider(true);

        var options = services.GetRequiredService<IOptions<LettuceEncryptOptions>>();
        return options.Value;
    }
}
