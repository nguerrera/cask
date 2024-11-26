// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO.Hashing;

using Xunit;

namespace CommonAnnotatedSecurityKeys.Tests;

public abstract class CaskTestsBase
{
    protected CaskTestsBase(ICask cask)
    {
        Cask = cask;
    }

    protected ICask Cask { get; }

    [Theory, InlineData(16), InlineData(32), InlineData(64)]
    public void CaskSecrets_IsCask(int secretEntropyInBytes)
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                          allocatorCode: "88",
                                          reserved: null,
                                          secretEntropyInBytes);

        IsCaskValidate(key);
    }

    [Theory, InlineData(16), InlineData(32), InlineData(64)]
    public void CaskSecrets_GenerateKey_Basic(int secretEntropyInBytes)
    {
        string key = Cask.GenerateKey(providerSignature: "TEST",
                                      allocatorCode: "88",
                                      reserved: "ABCD",
                                      secretEntropyInBytes);

        byte[] keyBytes = UrlSafeBase64.ConvertFromString(key);
        Assert.True(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

        IsCaskValidate(key);

    }

    [Theory]
    [InlineData(16, 2023), InlineData(16, 2088)]
    [InlineData(32, 2023), InlineData(32, 2088)]
    [InlineData(64, 2023), InlineData(64, 2088)]
    public void CaskSecrets_GenerateKey_InvalidTimestamps(int secretEntropyInBytes, int invalidYear)
    {
        // The CASK standard timestamp is only valid from 2024 - 2087
        // (where the base64-encoded character 'A' indicates 2024, and
        // the last valid base64 character '_' indicates 2087.

        for (int month = 0; month < 12; month++)
        {
            using var _ = Cask.MockUtcNow(
                () => new DateTimeOffset(invalidYear, 1 + month, 1, 0, 0, 0, TimeSpan.Zero));

            var action = () => Cask.GenerateKey(providerSignature: "TEST",
                                                allocatorCode: "88",
                                                reserved: "ABCD",
                                                secretEntropyInBytes);

            Assert.Throws<ArgumentOutOfRangeException>(action);
        }
    }

    [Theory, InlineData(16), InlineData(32), InlineData(64)]
    public void CaskSecrets_GenerateKey_ValidTimestamps(int secretEntropyInBytes)
    {
        // Every year from 2024 - 2087 should produce a valid key.
        // We trust that the CASK standard will be long dead by
        // 2087 or perhaps simply all or most programmers will be.
        for (int year = 0; year < 64; year++)
        {
            for (int month = 0; month < 12; month++)
            {
                using var _ = Cask.MockUtcNow(
                    () => new DateTimeOffset(2024 + year, 1 + month, 1, 0, 0, 0, TimeSpan.Zero));

                string key = Cask.GenerateKey(providerSignature: "TEST",
                                                allocatorCode: "88",
                                                reserved: "ABCD",
                                                secretEntropyInBytes);

                IsCaskValidate(key);
            }
        }
    }

    private void IsCaskValidate(string key)
    {
        // Positive test cases.
        Assert.True(Cask.IsCask(key), $"'GenerateKey' output failed 'IsCask(string)': {key}");

        byte[] keyBytes = UrlSafeBase64.ConvertFromString(key);
        Assert.True(Cask.IsCask(keyBytes), $"'GenerateKey' output failed 'IsCask(byte[]): {key}'.");

        // Now we will modify the CASK standard fixed signature only ('JQQJ').
        // We will recompute the checksum and replace it, to ensure that it 
        // is the signature check, and not the checksum hash, that
        // invalidates the secret.

        int signatureIndex = key.LastIndexOf("JQQJ");
        for (int i = 0; i < 4; i++)
        {
            // Cycle through XQQJ, JXQJ, JQXJ, and JQQX.
            string modifiedKey = $"{key.Substring(0, signatureIndex + i)}X{key.Substring(signatureIndex + i + 1)}";

            Span<byte> toChecksum = new Span<byte>(keyBytes, 0, keyBytes.Length - 3);

            byte[] crc32Bytes = new byte[4];
            Crc32.Hash(toChecksum, crc32Bytes);

            string checksum = UrlSafeBase64.ConvertToString(crc32Bytes).Substring(0, 4);
            modifiedKey = $"{modifiedKey.Substring(0, modifiedKey.Length - 4)}{checksum}";

            Assert.False(Cask.IsCask(modifiedKey), $"'IsCask(string)' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");

            keyBytes = UrlSafeBase64.ConvertFromString(modifiedKey);
            Assert.False(Cask.IsCask(keyBytes), $"'IsCask(byte[])' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");
        }

        // Having established that the key is a CASK secret, we now will modify
        // every character in the key, which should invalidate the checksum.

        for (int i = 0; i < key.Length; i++)
        {
            char replacement = key[i] == '-' ? '_' : '-';
            string modifiedKey = $"{key.Substring(0, i)}{replacement}{key.Substring(i + 1)}";

            bool result = Cask.IsCask(modifiedKey);
            Assert.False(result, $"'IsCask(string)' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");

            keyBytes = UrlSafeBase64.ConvertFromString(modifiedKey);
            result = Cask.IsCask(keyBytes);
            Assert.False(result, $"'IsCask(byte[])' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");
        }
    }
}