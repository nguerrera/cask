// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Frozen;

namespace CommonAnnotatedSecurityKeys;

public static class UrlSafeBase64
{
    private static readonly char[] s_orderedUrlSafeChars = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    ];

    internal static ReadOnlySpan<char> OrderedUrlSafeChars => s_orderedUrlSafeChars;

    internal static readonly FrozenSet<char> UrlSafeChars = s_orderedUrlSafeChars.ToFrozenSet();

    public static byte[] ConvertFromString(string base64)
    {
        return Convert.FromBase64String(FromUrlSafe(base64));
    }

    public static string ConvertToString(byte[] bytes)
    {
        return ToUrlSafe(Convert.ToBase64String(bytes));
    }

    private static string FromUrlSafe(string base64)
    {
        return base64.Replace('-', '+').Replace('_', '/');
    }

    private static string ToUrlSafe(string base64)
    {
        return base64.Replace('+', '-').Replace('/', '_');
    }
}