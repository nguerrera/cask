// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys.Benchmarks;

internal static class BenchmarkTestData
{
    public const string TestDerivationInput = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
    public const string TestProviderSignature = "TEST";
    public const string TestAllocatorCode = "88";
    public const string TestProviderData = "0123456789ABCDEF";
    public const int TestSecretEntropyInBytes = 32;

    public static readonly string TestCaskSecret = new GenerateKeyBenchmark().GenerateKey_Cask();
    public static readonly string TestNonIdentifiableSecret = new GenerateKeyBenchmark().GenerateKey_Floor();

    public static readonly string TestCaskHash = new GenerateHashBenchmark().GenerateHash_Cask();
    public static readonly string TestNonIdentifiableHash = new GenerateHashBenchmark().GenerateHash_Floor();
}
