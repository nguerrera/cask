// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CommonAnnotatedSecurityKeys
{
    internal static class CaskConstants
    {
        [ThreadStatic]
        private static readonly Lazy<Crc32> crc32 =
            new(() => new Crc32());

        [ThreadStatic]
        private static readonly Lazy<SHA256> sha256 =
            new(() => SHA256.Create());

        [ThreadStatic]
        private static readonly Lazy<HMACSHA256> caskHmac256 =
            new(() => new HMACSHA256(Encoding.UTF8.GetBytes("Cask_v1")));

        [ThreadStatic]
        private static readonly Lazy<RandomNumberGenerator> rng =
            new(() => RandomNumberGenerator.Create());

        public static string CaskSignature => "JQQJ";

        public static byte[] CaskSignatureBytes => Convert.FromBase64String(CaskSignature);

        public static readonly Regex CaskKeyRegex = new Regex("(^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{4}){6,}JQQJ[A-Za-z0-9_-]{12}($|[^A-Za-z0-9_-])", RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.CultureInvariant);

        public static Crc32 Crc32
        {
            get { return crc32.Value; }
        }

        public static SHA256 Sha256
        {
            get { return sha256.Value; }
        }

        public static HMACSHA256 Hmac256
        {
            get { return caskHmac256.Value; }
        }

        public static RandomNumberGenerator Rng
        {
            get { return rng.Value; }
        }
    }
}
