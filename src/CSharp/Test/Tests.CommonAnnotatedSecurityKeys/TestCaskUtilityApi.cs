// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommonAnnotatedSecurityKeys;

using System;

namespace Tests.CommonAnnotatedSecurityKeys
{
    internal class TestCaskUtilityApi : CaskUtilityApi
    {
        public Func<DateTimeOffset> GetCurrentDateTimeUtcFunc;

        public Func<byte[], byte[]> ComputeCrc32HashFunc;

        public override DateTimeOffset GetCurrentDateTimeUtc()
        {
            return GetCurrentDateTimeUtcFunc == null
                ? base.GetCurrentDateTimeUtc()
                : GetCurrentDateTimeUtcFunc();
        }

        public override byte[] ComputeCrc32Hash(Span<byte> toChecksum)
        {
            return ComputeCrc32HashFunc == null
                ? base.ComputeCrc32Hash(toChecksum)
                : ComputeCrc32HashFunc(toChecksum.ToArray());
        }
    }
}
