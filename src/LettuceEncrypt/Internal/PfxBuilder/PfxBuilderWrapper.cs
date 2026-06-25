// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.PfxBuilder;

internal sealed class PfxBuilderWrapper : IPfxBuilder
{
    private readonly Certify.ACME.Anvil.Pkcs.PfxBuilder _pfxBuilder;

    public PfxBuilderWrapper(Certify.ACME.Anvil.Pkcs.PfxBuilder pfxBuilder)
    {
        _pfxBuilder = pfxBuilder;
    }

    public void AddIssuer(byte[] certificate)
        => _pfxBuilder.AddIssuer(certificate);

    public byte[] Build(string friendlyName, string password)
        => _pfxBuilder.Build(friendlyName, password);
}
