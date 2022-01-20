// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Net.Security;
using LettuceEncrypt.Internal;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.Hosting;

/// <summary>
/// Methods for configuring Kestrel.
/// </summary>
public static class LettuceEncryptKestrelHttpsOptionsExtensions
{
    private const string MissingServicesMessage =
        "Missing required LettuceEncrypt services. Did you call '.AddLettuceEncrypt()' to add these your DI container?";

    /// <summary>
    /// Configured LettuceEncrypt on this HTTPS endpoint for Kestrel.
    /// </summary>
    /// <param name="httpsOptions">Kestrel's HTTPS configuration</param>
    /// <param name="applicationServices"></param>
    /// <returns>The original HTTPS options with some required settings added to it.</returns>
    /// <exception cref="InvalidOperationException">
    /// Raised if <see cref="LettuceEncryptServiceCollectionExtensions.AddLettuceEncrypt(Microsoft.Extensions.DependencyInjection.IServiceCollection)"/>
    /// has not been used to add required services to the application service provider
    /// </exception>
    public static HttpsConnectionAdapterOptions UseLettuceEncrypt(
        this HttpsConnectionAdapterOptions httpsOptions,
        IServiceProvider applicationServices)
    {
        var selector = applicationServices.GetService<IServerCertificateSelector>();

        if (selector is null)
        {
            throw new InvalidOperationException(MissingServicesMessage);
        }

#if NETCOREAPP3_1_OR_GREATER
        var tlsResponder = applicationServices.GetService<TlsAlpnChallengeResponder>();
        if (tlsResponder is null)
        {
            throw new InvalidOperationException(MissingServicesMessage);
        }

        return httpsOptions.UseLettuceEncrypt(selector, tlsResponder);

#elif NETSTANDARD2_0
        return httpsOptions.UseServerCertificateSelector(selector);
#else
#error Update TFMs
#endif
    }
    /// <summary>
    /// Configured LettuceEncrypt on this listening endpoint for Kestrel.
    /// </summary>
    /// <param name="listenOptions">Kestrel's listen configuration</param>
    /// <param name="applicationServices"></param>
    /// <returns>The original HTTPS options with some required settings added to it.</returns>
    /// <exception cref="InvalidOperationException">
    /// Raised if <see cref="LettuceEncryptServiceCollectionExtensions.AddLettuceEncrypt(Microsoft.Extensions.DependencyInjection.IServiceCollection)"/>
    /// has not been used to add required services to the application service provider
    /// </exception>
    public static ListenOptions UseLettuceEncrypt(
        this ListenOptions listenOptions,
        IServiceProvider applicationServices)
    {
#if NET6_0_OR_GREATER
            var selector = applicationServices.GetService<IServerCertificateSelector>();

            if (selector is null)
            {
                throw new InvalidOperationException(MissingServicesMessage);
            }

            var tlsResponder = applicationServices.GetService<TlsAlpnChallengeResponder>();
            if (tlsResponder is null)
            {
                throw new InvalidOperationException(MissingServicesMessage);
            }

            return listenOptions.UseLettuceEncrypt(selector, tlsResponder);
#elif NETCOREAPP3_1_OR_GREATER || NETSTANDARD2_0
            return listenOptions;
#else
#error Update TFMs
#endif
    }
#if NET6_0_OR_GREATER
        internal static ListenOptions UseLettuceEncrypt(
            this ListenOptions listenOptions,
            IServerCertificateSelector selector,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder)
        {
            return listenOptions.UseHttps(new TlsHandshakeCallbackOptions()
            {
                OnConnection = async ctx =>
                {
                    var options = new SslServerAuthenticationOptions();

                    tlsAlpnChallengeResponder.OnSslAuthenticate(ctx.Connection, options);

                    options.ServerCertificate = await selector.SelectAsync(ctx.Connection, ctx.ClientHelloInfo.ServerName);

                    return options;
                }
            });
        }
#endif
#if NETCOREAPP3_1_OR_GREATER
    internal static HttpsConnectionAdapterOptions UseLettuceEncrypt(
        this HttpsConnectionAdapterOptions httpsOptions,
        IServerCertificateSelector selector,
        TlsAlpnChallengeResponder tlsAlpnChallengeResponder
    )
    {
        // Check if this handler is already set. If so, chain our handler before it.
        var otherHandler = httpsOptions.OnAuthenticate;
        httpsOptions.OnAuthenticate = (ctx, options) =>
        {
            tlsAlpnChallengeResponder.OnSslAuthenticate(ctx, options);
            otherHandler?.Invoke(ctx, options);
        };

        httpsOptions.UseServerCertificateSelector(selector);
        return httpsOptions;
    }
#elif NETSTANDARD2_0
#else
#error Update TFMs
#endif
}