// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommonAnnotatedSecurityKeys;

using System;
using System.Diagnostics.CodeAnalysis;

namespace Tests.CommonAnnotatedSecurityKeys
{
    internal class TestCaskUtilityApi : ICaskUtilityApi
    {
        public Func<DateTimeOffset> GetCurrentDateTimeUtcFunc = () => DateTimeOffset.UtcNow;

        public DateTimeOffset GetCurrentDateTimeUtc()
        {
            return GetCurrentDateTimeUtcFunc();
        }
    }
}
