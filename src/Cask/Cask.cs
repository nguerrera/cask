// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys;

public static class Cask
{
    public static string Signature => "JQQJ";

    public static Regex KeyRegex => KeyRegexLazy.Value;

    public static bool IsCask(string key)
    {
        if (Signature[0] != key[key.Length - 16] ||
            Signature[1] != key[key.Length - 15] ||
            Signature[2] != key[key.Length - 14] ||
            Signature[3] != key[key.Length - 13])
        {
            return false;
        }

        byte[] keyBytes = UrlSafeBase64.ConvertFromString(key);
        return IsCask(keyBytes);
    }

    public static bool IsCask(ReadOnlySpan<byte> keyBytes)
    {
        // This check ensures that 3 bytes of fixed signature are present
        // where they belong. We next hash the key and ensure the first
        // three bytes of the hash are present where they belong. This
        // leads to a chance of collision of 1 in 2 ^ 48, or
        // 1 in 281,474,976,710,656, or ~1 million times less likely than
        // winning the Powerball lottery.
        if (s_signatureBytes[0] != keyBytes[keyBytes.Length - 12] ||
            s_signatureBytes[1] != keyBytes[keyBytes.Length - 11] ||
            s_signatureBytes[2] != keyBytes[keyBytes.Length - 10])
        {
            return false;
        }

        ReadOnlySpan<byte> toChecksum = keyBytes.Slice(0, keyBytes.Length - 3);
        Span<byte> crc32Bytes = stackalloc byte[4];
        Crc32.Hash(toChecksum, crc32Bytes);

        return
            crc32Bytes[0] == keyBytes[keyBytes.Length - 3] &&
            crc32Bytes[1] == keyBytes[keyBytes.Length - 2] &&
            crc32Bytes[2] == keyBytes[keyBytes.Length - 1];
    }


    public static string GenerateKey(string providerSignature,
                              string allocatorCode,
                              string? reserved = null,
                              int secretEntropyInBytes = 32)
    {
        byte[] reservedBytes = reserved == null
            ? Array.Empty<byte>()
            : UrlSafeBase64.ConvertFromString(reserved);

        byte[] providerSignatureBytes = Convert.FromBase64String(providerSignature);

        byte[] keyBytes = GenerateKeyBytes(providerSignatureBytes,
                                           allocatorCode,
                                           reservedBytes,
                                           secretEntropyInBytes);

        return UrlSafeBase64.ConvertToString(keyBytes);
    }

    public static byte[] GenerateKeyBytes(byte[] providerSignature,
                                   string allocatorCode,
                                   byte[]? reserved = null,
                                   int secretEntropyInBytes = 32)
    {
        // Ensure that the randomBytesCount is a multiple of 3. We keep all data
        // aligned along a 3-byte boundary to ensure consistent base64 encoding
        // in the key for fixed components.
        secretEntropyInBytes = RoundUpToMultipleOf(secretEntropyInBytes, 3);

        byte[] allocatorAndTimestampBytes = GenerateAllocatorAndTimestampBytes(allocatorCode);

        int reservedLength = (reserved?.Length ?? 0);

        int keyLength = secretEntropyInBytes +
                        reservedLength +
                        3 + /* always 3 */
                        allocatorAndTimestampBytes.Length + /* always 3 */
                        providerSignature.Length +
                        3;  // Partial CRC32 is 3 bytes.

        // Start by filling the entire key with random bytes.
        byte[] keyBytes = new byte[keyLength];
        RandomNumberGenerator.Fill(keyBytes);

        int reservedOffset = secretEntropyInBytes;
        int caskSignatureOffset = reservedOffset + reservedLength;
        int allocatorAndTimestampOffset = caskSignatureOffset + 3;
        int providerSignatureOffset = allocatorAndTimestampOffset + allocatorAndTimestampBytes.Length;
        int partialHashOffset = providerSignatureOffset + providerSignature.Length;

        // Copy optional reserved bytes, if provided.
        Array.Copy(reserved ?? Array.Empty<byte>(), 0, keyBytes, reservedOffset, reserved?.Length ?? 0);

        // Copy 'JQQJ', the CASK standard fixed signature, into the key.
        Array.Copy(s_signatureBytes, 0, keyBytes, caskSignatureOffset, 3);

        // Copy the allocator and timestamp into the key.
        Array.Copy(allocatorAndTimestampBytes, 0, keyBytes, allocatorAndTimestampOffset, allocatorAndTimestampBytes.Length);

        // Copy the key provider's signature into the key.
        Array.Copy(providerSignature, 0, keyBytes, providerSignatureOffset, providerSignature.Length);

        Span<byte> toChecksum = new Span<byte>(keyBytes, 0, partialHashOffset);

        Span<byte> crc32Bytes = stackalloc byte[4];
        Crc32.Hash(toChecksum, crc32Bytes);

        crc32Bytes.Slice(0, 3).CopyTo(keyBytes.AsSpan().Slice(partialHashOffset, 3));

        // Done.
        return keyBytes;
    }

    internal static byte[] GenerateAllocatorAndTimestampBytes(string allocatorCode)
    {
        if (!ContainsOnlyUrlSafeBase64Characters(allocatorCode))
        {
            throw new ArgumentException($"Allocator code includes characters that are not legal URL-safe base64: '{allocatorCode}");
        }

        DateTimeOffset utcNow = GetUtcNow();

        if (utcNow.Year < 2024 || utcNow.Year > 2087)
        {
            throw new ArgumentOutOfRangeException("CASK requires the current year to be between 2024 and 2087.");
        }

        char yearsSince2024 = UrlSafeBase64.OrderedUrlSafeChars[utcNow.Year - 2024];
        char zeroIndexedMonth = UrlSafeBase64.OrderedUrlSafeChars[utcNow.Month - 1];
        string allocatorAndTimestamp = $"{allocatorCode}{yearsSince2024}{zeroIndexedMonth}";
        return UrlSafeBase64.ConvertFromString(allocatorAndTimestamp);
    }

    private static bool ContainsOnlyUrlSafeBase64Characters(string allocatorCode)
    {
        foreach (char c in allocatorCode)
        {
            if (!UrlSafeBase64.UrlSafeChars.Contains(c))
            {
                return false;
            }
        }

        return true;
    }

    public static string GenerateHash(byte[] derivationInput, byte[] secret, int secretEntropyInBytes)
    {
        byte[] hash = GenerateHashedSignatureBytes(derivationInput, secret, secretEntropyInBytes);
        return UrlSafeBase64.ConvertToString(hash);
    }

    internal static byte[] GenerateHashedSignatureBytes(byte[] derivationInput, byte[] secret, int secretEntropyInBytes)
    {
        byte[] allocatorAndTimeStampBytes = new byte[3];

        secretEntropyInBytes = RoundUpToMultipleOf(secretEntropyInBytes, 3);
        int reservedBytesLength = secret.Length - 12 - secretEntropyInBytes;

        using var hmac = new HMACSHA256(secret);
        byte[] hash = hmac.ComputeHash(derivationInput);

        byte[] hashedSignature = new byte[33 + 12 + reservedBytesLength];

        // Move the literal hash over.
        Array.Copy(hash, 0, hashedSignature, 0, 32);

        // Recapitulate other data.
        int reservedOffset = 33;
        Array.Copy(secret, secretEntropyInBytes, hashedSignature, reservedOffset, reservedBytesLength);

        int standardOffset = reservedOffset + reservedBytesLength;
        Array.Copy(s_signatureBytes, 0, hashedSignature, standardOffset, 3);

        byte[] secretAllocatorAndTimeStampBytes = new byte[3];
        int secretAllocatorAndTimeStampBytesOffset = secretEntropyInBytes + reservedBytesLength + 3;
        Array.Copy(secret, secretAllocatorAndTimeStampBytesOffset, secretAllocatorAndTimeStampBytes, 0, 3);

        DateTimeOffset utcNow = GetUtcNow();
        byte yearsSince2024 = (byte)(utcNow.Year - 2024);
        byte zeroIndexedMonth = (byte)(utcNow.Month - 1);

        int? metadata = (61 << 18) | (61 << 12) | (yearsSince2024 << 6) | zeroIndexedMonth;
        byte[] metadataBytes = BitConverter.GetBytes(metadata.Value);

        int allocatorAndTimestampOffset = standardOffset + 3;

        hashedSignature[allocatorAndTimestampOffset] = secret[secretAllocatorAndTimeStampBytesOffset];
        hashedSignature[allocatorAndTimestampOffset + 1] = (byte)((secret[secretAllocatorAndTimeStampBytesOffset + 1] & 0xf0) | (yearsSince2024 >> 4 & 0x3));
        hashedSignature[allocatorAndTimestampOffset + 2] = (byte)(yearsSince2024 << 6 | zeroIndexedMonth);

        int secretProviderSignatureBytesOffset = secretAllocatorAndTimeStampBytesOffset + 3;
        int providerSignatureBytesOffset = allocatorAndTimestampOffset + 3;
        Array.Copy(secret, secretProviderSignatureBytesOffset, hashedSignature, providerSignatureBytesOffset, 3);

        Span<byte> toChecksum = new Span<byte>(hashedSignature, 0, providerSignatureBytesOffset + 3);

        Span<byte> crc32Bytes = stackalloc byte[4];
        Crc32.Hash(toChecksum, crc32Bytes);

        int crc32HashOffset = providerSignatureBytesOffset + 3;
        crc32Bytes.Slice(0, 3).CopyTo(hashedSignature.AsSpan().Slice(crc32HashOffset, 3));

        return hashedSignature;
    }

    public static bool CompareHash(byte[] candidateHash, byte[] derivationInput, byte[] secret, int secretEntropyInBytes = 32)
    {
        byte[] computedHash = GenerateHashedSignatureBytes(derivationInput, secret, secretEntropyInBytes);
        return CryptographicOperations.FixedTimeEquals(computedHash, candidateHash);
    }

    internal static IDisposable MockUtcNow(GetUtcNowFunc getUtcNow)
    {
        t_mockedGetUtcNow = getUtcNow;
        return new Disposable(() => t_mockedGetUtcNow = null);
    }

    internal static IDisposable MockFillRandom(FillRandomAction fillRandom)
    {
        t_mockedFillRandom = fillRandom;
        return new Disposable(() => t_mockedFillRandom = null);
    }

    private static int RoundUpToMultipleOf(this int value, int multiple)
    {
        return (value + multiple - 1) / multiple * multiple;
    }

    private static void FillRandom(Span<byte> buffer)
    {
        if (t_mockedFillRandom != null)
        {
            t_mockedFillRandom(buffer);
            return;
        }

        RandomNumberGenerator.Fill(buffer);
    }

    private static DateTimeOffset GetUtcNow()
    {
        if (t_mockedGetUtcNow != null)
        {
            return t_mockedGetUtcNow();
        }

        return DateTimeOffset.UtcNow;
    }

    private static class KeyRegexLazy
    {
        public static readonly Regex Value = new(
            """(^|[^A-Za-z0-9+/-_])([A-Za-z0-9-_]{4}){6,}JQQJ[A-Za-z0-9-_]{12}($|[^A-Za-z0-9+/-_])""",
            RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant
        );
    }

    private static readonly byte[] s_signatureBytes = UrlSafeBase64.ConvertFromString(Signature);
    [ThreadStatic] private static GetUtcNowFunc? t_mockedGetUtcNow;
    [ThreadStatic] private static FillRandomAction? t_mockedFillRandom;
}

internal delegate void FillRandomAction(Span<byte> buffer);

internal delegate DateTimeOffset GetUtcNowFunc();

internal sealed class Disposable(Action dispose) : IDisposable
{
    public void Dispose() => dispose();
}