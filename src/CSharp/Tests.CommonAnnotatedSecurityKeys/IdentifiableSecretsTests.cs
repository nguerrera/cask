// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

using CommonAnnotatedSecurityKeys;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.CommonAnnotatedSecurityKeys
{
    [TestClass, ExcludeFromCodeCoverage]
    public class CaskSecretsTests
    {
        private static readonly IEnumerable<ICask> casks;

        static CaskSecretsTests()
        {
            casks = new[]
            {
                new CSharpCask(),
                /* TBD: new CPlusPlusCask(), Pinvoke to C++ implementation */
                /* TBD: new RustCask(), Foreign function interface to Rust implementation */
            };
        }

        [TestMethod]
        public void CaskSecrets_IsCask()
        {
            foreach (ICask cask in casks)
            {
                foreach (int secretEntropyInBytes in new[] { 16, 32, 64 })
                {
                    string key = cask.GenerateKey(providerSignature: "TEST",
                                                  allocatorCode: "88",
                                                  reserved: null,
                                                  secretEntropyInBytes);

                    IsCaskValidate(cask, key);
                }
            }
        }

        [TestMethod]
        public void CaskSecrets_GenerateKey()
        {
            foreach (ICask cask in casks)
            {
                foreach (int secretEntropyInBytes in new[] { 16, 32, 64 })
                {
                    string key = cask.GenerateKey(providerSignature: "TEST",
                                                  allocatorCode: "88",
                                                  reserved: "ABCD",
                                                  secretEntropyInBytes);

                    byte[] keyBytes = Convert.FromBase64String(key.FromUrlSafe());
                    Assert.IsTrue(keyBytes.Length % 3 == 0, "'GenerateKey' output wasn't aligned on a 3-byte boundary.");

                    IsCaskValidate(cask, key);
                }
            }
        }

        private void IsCaskValidate(ICask cask, string key)
        {
            // Positive test cases.
            Assert.IsTrue(cask.IsCask(key), $"'GenerateKey' output failed 'IsCask(string)': {key}");

            byte[] keyBytes = Convert.FromBase64String(key.FromUrlSafe());
            Assert.IsTrue(cask.IsCask(keyBytes), $"'GenerateKey' output failed 'IsCask(byte[]): {key}'.");

            // Now we will modify the CASK standard fixed signature only ('JQQJ').
            // We will recompute the checksum and replace it, to ensure that it 
            // is the signature check, and not the checksum hash, that
            // invalidates the secret.

            int signatureIndex = key.LastIndexOf("JQQJ");
            for (int i = 0; i < 4; i++)
            {
                // Cycle through XQQJ, JXQJ, JQXJ, and JQQX.
                string modifiedKey = $"{key.Substring(0, signatureIndex + i)}X{key.Substring(signatureIndex + i + 1)}";

                Span<byte> span = new Span<byte>(keyBytes, 0, keyBytes.Length - 3);
                byte[] hashBytes = CSharpCask.ComputeCrc32Hash(span);

                string checksum = Convert.ToBase64String(hashBytes).ToUrlSafe().Substring(0, 4);
                modifiedKey = $"{modifiedKey.Substring(0, modifiedKey.Length - 4)}{checksum}";

                Assert.IsFalse(cask.IsCask(modifiedKey), $"'IsCask(string)' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");

                keyBytes = Convert.FromBase64String(modifiedKey.FromUrlSafe());
                Assert.IsFalse(cask.IsCask(keyBytes), $"'IsCask(byte[])' unexpectedly succeeded with modified 'JQQJ' signature: {modifiedKey}");
            }

            // Having established that the key is a CASK secret, we now will modify
            // every character in the key, which should invalidate the checksum.

            for (int i = 0; i < key.Length; i++)
            {
                char replacement = key[i] == '-' ? '_' : '-';
                string modifiedKey = $"{key.Substring(0, i)}{replacement}{key.Substring(i + 1)}";

                bool result = cask.IsCask(modifiedKey);
                Assert.IsFalse(result, $"'IsCask(string)' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");

                keyBytes = Convert.FromBase64String(modifiedKey.FromUrlSafe());
                result = cask.IsCask(keyBytes);
                Assert.IsFalse(result, $"'IsCask(byte[])' unexpectedly succeeded after invalidating checksum: {modifiedKey}. Original key was: {key}");
            }
        }
    }
}