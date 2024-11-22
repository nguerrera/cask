// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace CommonAnnotatedSecurityKeys
{
    public static class CaskSecrets
    {
        internal static readonly ICask _cask = new CSharpCask();

        public static string GenerateHash(byte[] derivationInput, byte[] secret, int secretEntropyInBytes = 32)
        {
            return _cask.GenerateHash(derivationInput, secret, secretEntropyInBytes);
        }

        public static bool CompareHash(byte[] candidateHash, byte[] derivationIntput, byte[] secret, int secretEntropyInBytes = 32)
        {
            return _cask.CompareHash(candidateHash, derivationIntput, secret, secretEntropyInBytes);
        }


        public static string GenerateKey(string providerSignature, string allocatorCode, string reserved = null, int secretEntropyInBytes = 32)
        {
            return _cask.GenerateKey(providerSignature, allocatorCode, reserved, secretEntropyInBytes);
        }

        public static bool IsCask(string key)
        {
            return _cask.IsCask(key);
        }

        public static bool IsCask(byte[] keyBytes)
        {
            return _cask.IsCask(keyBytes);
        }
    }
}
