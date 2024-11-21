// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text;

namespace CommonAnnotatedSecurityKeys
{
    internal class CSharpCask : ICask
    {
        public bool IsCask(string key)
        {
            if (CaskConstants.CaskSignature[0] != key[key.Length - 16] ||
                CaskConstants.CaskSignature[1] != key[key.Length - 15] ||
                CaskConstants.CaskSignature[2] != key[key.Length - 14] ||
                CaskConstants.CaskSignature[3] != key[key.Length - 13])
            {
                return false;
            }
            byte[] keyBytes = Convert.FromBase64String(key.FromUrlSafe());
            return IsCask(keyBytes);
        }

        public bool IsCask(byte[] keyBytes)
        {
            // This check ensures that 3 bytes of fixed signature are present
            // where they belong. We next hash the key and ensure the first
            // three bytes of the hash are present where they belong. This
            // leads to a chance of collision of 1 in 2 ^ 48, or
            // 1 in 281,474,976,710,656, or ~1 million times less likely than
            // winning the Powerball lottery.
            if (CaskConstants.CaskSignatureBytes[0] != keyBytes[keyBytes.Length - 12] ||
                CaskConstants.CaskSignatureBytes[1] != keyBytes[keyBytes.Length - 11] ||
                CaskConstants.CaskSignatureBytes[2] != keyBytes[keyBytes.Length - 10])
            {
                return false;
            }

            Span<byte> toChecksum = new Span<byte>(keyBytes, 0, keyBytes.Length - 3);
            byte[] crc32Bytes = ComputeCrc32Hash(toChecksum);

            return
                crc32Bytes[0] == keyBytes[keyBytes.Length - 3] &&
                crc32Bytes[1] == keyBytes[keyBytes.Length - 2] &&
                crc32Bytes[2] == keyBytes[keyBytes.Length - 1];
        }

        public string GenerateKey(string providerSignature,
                                  string allocatorCode,
                                  string reserved = null,
                                  int secretEntropyInBytes = 32)
        {
            byte[] reservedBytes = reserved == null 
                ? Array.Empty<byte>()
                : Convert.FromBase64String(reserved.FromUrlSafe());

            byte[] providerSignatureBytes = Convert.FromBase64String(providerSignature);

            byte[] keyBytes = GenerateKeyBytes(providerSignatureBytes,
                                               allocatorCode,
                                               reservedBytes,
                                               secretEntropyInBytes);

            return Convert.ToBase64String(keyBytes).ToUrlSafe();
        }

        public byte[] GenerateKeyBytes(byte[] providerSignature,
                                       string allocatorCode,
                                       byte[] reserved = null,
                                       int secretEntropyInBytes = 32,
                                       char testChar = default)
        {
            // Ensure that the randomBytesCount is a multiple of 3. We keep all data
            // aligned along a 3-byte boundary to ensure consistent base64 encoding
            // in the key for fixed components.
            secretEntropyInBytes = secretEntropyInBytes.RoundUpToMultipleOf(3);

            byte[] allocatorAndTimestampBytes = GenerateAllocatorAndTimestampBytes(allocatorCode);

            int reservedLength = (reserved?.Length ?? 0);

            int keyLength = secretEntropyInBytes +
                            reservedLength +
                            3 + /* always 3 */
                            allocatorAndTimestampBytes.Length + /* always 3 */
                            providerSignature.Length +
                            3;  // Partial HMAC256 is 3 bytes.

            // Start by filling the entire key with random bytes.
            byte[] keyBytes = new byte[keyLength];

            if (testChar == default)
            {
                CaskConstants.Rng.GetBytes(keyBytes);
            }
            else
            {
                string randomComponent = new string(testChar, secretEntropyInBytes.RoundUpToMultipleOf(3));
                Array.Copy(Convert.FromBase64String(randomComponent), 0, keyBytes, 0, secretEntropyInBytes);
            }

            int reservedOffset = secretEntropyInBytes;
            int caskSignatureOffset = reservedOffset + reservedLength;
            int allocatorAndTimestampOffset = caskSignatureOffset + 3;
            int providerSignatureOffset = allocatorAndTimestampOffset + allocatorAndTimestampBytes.Length;
            int partialHashOffset = providerSignatureOffset + providerSignature.Length;

            // Copy optional reserved bytes, if provided.
            Array.Copy(reserved ?? new byte[] { }, 0, keyBytes, reservedOffset, reserved?.Length ?? 0);

            // Copy 'JQQJ', the CASK standard fixed signature, into the key.
            Array.Copy(CaskConstants.CaskSignatureBytes, 0, keyBytes, caskSignatureOffset, 3);

            // Copy the allocator and timestamp into the key.
            Array.Copy(allocatorAndTimestampBytes, 0, keyBytes, allocatorAndTimestampOffset, allocatorAndTimestampBytes.Length);

            // Copy the key provider's signature into the key.
            Array.Copy(providerSignature, 0, keyBytes, providerSignatureOffset, providerSignature.Length);

            Span<byte> toChecksum = new Span<byte>(keyBytes, 0, partialHashOffset);
            byte[] crc32Bytes = ComputeCrc32Hash(toChecksum);

            Array.Copy(crc32Bytes, 0, keyBytes, partialHashOffset, 3);

            // Done.
            return keyBytes;
        }

        internal static byte[] GenerateAllocatorAndTimestampBytes(string allocatorCode)
        {
            DateTime utcNow = DateTime.UtcNow;
            char yearsSince2024 = (char)('A' + utcNow.Year - 2024);
            char zeroIndexedMonth = (char)('A' + utcNow.Month - 1);
            string allocatorAndTimestamp = $"{allocatorCode}{yearsSince2024}{zeroIndexedMonth}";
            return Convert.FromBase64String(allocatorAndTimestamp);
        }

        public string GenerateHash(byte[] derivationInput, byte[] secret, int secretEntropyInBytes)
        {
            byte[] hash = GenerateHashedSignatureBytes(derivationInput, secret, secretEntropyInBytes);
            return Convert.ToBase64String(hash).ToUrlSafe();
        }

        internal byte[] GenerateHashedSignatureBytes(byte[] derivationInput, byte[] secret, int secretEntropyInBytes)
        {            
            byte[] allocatorAndTimeStampBytes = new byte[3];

            secretEntropyInBytes = secretEntropyInBytes.RoundUpToMultipleOf(3);
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
            Array.Copy(CaskConstants.CaskSignatureBytes, 0, hashedSignature, standardOffset, 3);

            byte[] secretAllocatorAndTimeStampBytes = new byte[3];
            int secretAllocatorAndTimeStampBytesOffset = secretEntropyInBytes + reservedBytesLength + 3;
            Array.Copy(secret, secretAllocatorAndTimeStampBytesOffset, secretAllocatorAndTimeStampBytes, 0, 3);

            byte yearsSince2024 = (byte)(DateTime.UtcNow.Year - 2024);
            byte zeroIndexedMonth = (byte)(DateTime.UtcNow.Month - 1);

            int? metadata = (61 << 18) | (61 << 12) | (yearsSince2024 << 6) | zeroIndexedMonth;
            byte[] metadataBytes = BitConverter.GetBytes(metadata.Value);

            int allocatorAndTimestampOffset = standardOffset + 3;

            hashedSignature[allocatorAndTimestampOffset] = secret[secretAllocatorAndTimeStampBytesOffset];
            hashedSignature[allocatorAndTimestampOffset + 1] = (byte)((secret[secretAllocatorAndTimeStampBytesOffset + 1] & 0xf0) | (yearsSince2024 >> 4 & 0x3));
            hashedSignature[allocatorAndTimestampOffset + 2] = (byte)(yearsSince2024 << 6 | zeroIndexedMonth);

            /*
            string allocatorAndTimeStamp = Convert.ToBase64String(secretAllocatorAndTimeStampBytes);
            byte[] allocatorAndTimestampBytes = GenerateAllocatorAndTimestampBytes(allocatorAndTimeStamp.Substring(0, 2));
            Array.Copy(allocatorAndTimestampBytes, 0, hashedSignature, allocatorAndTimestampOffset, allocatorAndTimestampBytes.Length);
            */

            int secretProviderSignatureBytesOffset = secretAllocatorAndTimeStampBytesOffset + 3;
            int providerSignatureBytesOffset = allocatorAndTimestampOffset + 3;
            Array.Copy(secret, secretProviderSignatureBytesOffset, hashedSignature, providerSignatureBytesOffset, 3);

            byte[] hashOfHash = CaskConstants.Hmac256.ComputeHash(hashedSignature, 0, hashedSignature.Length - 3);
            int hashOfHashOffset = providerSignatureBytesOffset + 3;
            Array.Copy(hashOfHash, 0, hashedSignature, hashOfHashOffset, 3);

            return hashedSignature;
        }

        public bool CompareHash(byte[] candidateHash, byte[] derivationInput, byte[] secret, int secretEntropyInBytes)
        {
            byte[] computedHash = GenerateHashedSignatureBytes(derivationInput, secret, 32);

            if (computedHash.Length != candidateHash.Length)
            {
                return false;
            }

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != candidateHash[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] ComputeCrc32Hash(Span<byte> toChecksum)
        {
            CaskConstants.Crc32.Reset();
            CaskConstants.Crc32.Append(toChecksum);
            byte[] hashBytes = new byte[4];
            CaskConstants.Crc32.GetHashAndReset(hashBytes);
            return hashBytes;
        }
    }
}
