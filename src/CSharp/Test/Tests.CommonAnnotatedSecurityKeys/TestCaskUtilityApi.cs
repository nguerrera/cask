// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommonAnnotatedSecurityKeys;

using System;

namespace Tests.CommonAnnotatedSecurityKeys
{
    internal class TestCaskUtilityApi : CaskUtilityApi
    {
        public Func<DateTimeOffset> GetCurrentDateTimeUtcFunc;

#pragma warning disable CS0649
        public Action<byte[], byte[]> ComputeCrc32HashAction;
#pragma warning restore CS0649

        public override DateTimeOffset GetCurrentDateTimeUtc()
        {
            return GetCurrentDateTimeUtcFunc == null
                ? base.GetCurrentDateTimeUtc()
                : GetCurrentDateTimeUtcFunc();
        }

        public override void ComputeCrc32Hash(ReadOnlySpan<byte> toChecksum, Span<byte> destination)
        {
            if (ComputeCrc32HashAction != null)
            {
                ComputeCrc32HashAction(toChecksum.ToArray(), destination.ToArray());
                return;
            }
            
            base.ComputeCrc32Hash(toChecksum, destination);
        }
    }
}
