// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

using BenchmarkDotNet.Attributes;

using static CommonAnnotatedSecurityKeys.Benchmarks.BenchmarkTestData;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

[MemoryDiagnoser]
public class GenerateHashBenchmark
{

    [Benchmark]
    public string GenerateHash_Cask()
    {
        CaskKey key = Cask.GenerateHash(TestDerivationInput, CaskKey.Create(TestCaskSecret), TestSecretEntropyInBytes);
        return key.ToString();
    }

    // What someone could do if they weren't using Cask and didn't get identifiable hashes.
    [Benchmark]
    public string GenerateHash_Floor()
    {
        Span<byte> secret = stackalloc byte[32];
        Base64Url.DecodeFromChars(TestNonIdentifiableSecret.AsSpan(), secret);

        Span<byte> derivationInput = stackalloc byte[Encoding.UTF8.GetMaxByteCount(TestDerivationInput.Length)];
        int bytesWritten = Encoding.UTF8.GetBytes(TestDerivationInput.AsSpan(), derivationInput);
        derivationInput = derivationInput[..bytesWritten];

        Span<byte> hashed = stackalloc byte[32];
        HMACSHA256.HashData(secret, derivationInput, hashed);
        string hash = Base64Url.EncodeToString(secret);
        return hash;
    }
}
