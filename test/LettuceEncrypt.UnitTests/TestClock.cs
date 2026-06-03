// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.IO;

namespace LettuceEncrypt.UnitTests;

internal class TestClock : IClock
{
    public DateTimeOffset Now { get; set; } = DateTimeOffset.Now;
}
