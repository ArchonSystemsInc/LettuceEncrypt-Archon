// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certify.ACME.Anvil;
using Certify.ACME.Anvil.Acme;

namespace LettuceEncrypt.Internal.PfxBuilder;

internal interface IPfxBuilderFactory
{
    IPfxBuilder FromChain(CertificateChain certificateChain, IKey certKey);
}
