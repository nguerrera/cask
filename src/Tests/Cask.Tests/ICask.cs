// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys.Tests;

/// <summary>
/// Provides a common interface matching <see cref="Cask"/> static class for testing purposes.
/// Allows for testing Cask implementations in other languages than C# with the same test suite.
/// The C# implementation simply forwards calls to the static methods on <see cref="Cask"/>.
/// </summary>
public interface ICask
{
    bool IsCask(string keyOrHash);

    bool IsCask(ReadOnlySpan<byte> keyOrHashBytes);

    string GenerateKey(string providerSignature,
                       string allocatorCode,
                       string? reserved = null,
                       int secretEntropyInBytes = 32);

    string GenerateHash(byte[] derivationInput,
                        byte[] secret,
                        int secretEntropyInBytes = 32);

    bool CompareHash(byte[] candidateHash,
                     byte[] derivationInput,
                     byte[] secret,
                     int secretEntropyInBytes = 32);

    internal IDisposable MockUtcNow(GetUtcNowFunc getUtcNow);

    internal IDisposable MockFillRandom(FillRandomAction fillRandom);
}