﻿// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.IO;

internal interface IClock
{
    DateTimeOffset Now { get; }
}
