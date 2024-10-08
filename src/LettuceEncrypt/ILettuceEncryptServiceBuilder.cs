// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt;

/// <summary>
/// An interface for building extension methods to extend LettuceEncrypt configuration.
/// </summary>
public interface ILettuceEncryptServiceBuilder
{
    /// <summary>
    /// The service collection.
    /// </summary>
    IServiceCollection Services { get; }
}
