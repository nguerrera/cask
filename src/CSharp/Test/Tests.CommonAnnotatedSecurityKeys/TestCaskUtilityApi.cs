// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommonAnnotatedSecurityKeys;

using System;

namespace Tests.CommonAnnotatedSecurityKeys
{
    internal class TestCaskUtilityApi : ICaskUtilityApi
    {
        public Func<DateTimeOffset> GetCurrentDateTimeUtcFunc = () => DateTimeOffset.UtcNow;

        public Func<byte[], byte[]> ComputeCrc32HashFunc = (byte[] toChecksum) =>
        {
            Span<byte> span = toChecksum;
            return CaskUtilityApi.Instance.ComputeCrc32Hash(span);
        };

        public DateTimeOffset GetCurrentDateTimeUtc()
        {
            return GetCurrentDateTimeUtcFunc();
        }

        public byte[] ComputeCrc32Hash(Span<byte> toChecksum)
        {
            return ComputeCrc32HashFunc(toChecksum.ToArray());
        }
    }
}
