// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CSharpCask = CommonAnnotatedSecurityKeys.Cask;

namespace CommonAnnotatedSecurityKeys.Tests;

public class CSharpCaskTests : CaskTestsBase
{
    public CSharpCaskTests() : base(new Implementation()) { }

    private sealed class Implementation : ICask
    {
        public bool CompareHash(byte[] candidateHash, byte[] derivationInput, byte[] secret, int secretEntropyInBytes = 32)
        {
            return CSharpCask.CompareHash(candidateHash, derivationInput, secret, secretEntropyInBytes);
        }

        public string GenerateHash(byte[] derivationInput, byte[] secret, int secretEntropyInBytes = 32)
        {
            return CSharpCask.GenerateHash(derivationInput, secret, secretEntropyInBytes);
        }

        public string GenerateKey(string providerSignature, string allocatorCode, string? reserved = null, int secretEntropyInBytes = 32)
        {
            return CSharpCask.GenerateKey(providerSignature, allocatorCode, reserved, secretEntropyInBytes);
        }

        public bool IsCask(string keyOrHash)
        {
            return CSharpCask.IsCask(keyOrHash);
        }

        public bool IsCask(ReadOnlySpan<byte> keyOrHashBytes)
        {
            return CSharpCask.IsCask(keyOrHashBytes);
        }

        IDisposable ICask.MockFillRandom(FillRandomAction fillRandom)
        {
            return CSharpCask.MockFillRandom(fillRandom);
        }

        IDisposable ICask.MockUtcNow(GetUtcNowFunc getUtcNow)
        {
            return CSharpCask.MockUtcNow(getUtcNow: getUtcNow);
        }
    }
}