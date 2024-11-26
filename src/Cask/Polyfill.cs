// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// NOTE: This file is only compiled when targeting .NET Framework and fills in
// BCL gaps there. The goal is to keep the main code reading as it would if we
// could target .NET 8 alone. We use some tricks like the global usings below to
// avoid using #if code.
//
// We also aim to keep this code simple, accepting that performance won't be as
// good on .NET Framework as it would be on .NET 8. We may allocate additional
// temporary objects and copy additional bytes, etc. in order to implement the
// .NET 8 BCL API shape with minimal complexity.
//
// Consumers with very high performance requirements should use .NET 8+.

global using CryptographicOperations = Polyfill.CryptographicOperations;
global using RandomNumberGenerator = Polyfill.RandomNumberGenerator;

using System.Runtime.CompilerServices;

// Suppress "IDE0130: Namespace does not match folder structure." This namespace
// is special. Its types replace/shadow BCL types, which is accomplished via
// global usings above.
#pragma warning disable IDE0130

namespace Polyfill;

internal static class CryptographicOperations
{
    // WARNING: DO NOT MODIFY EXCEPT TO UPDATE TO A LATER VERSION OF THE CODE FROM THE BCL. THIS IS HARDER THAN IT MAY SEEM TO GET RIGHT!
    // Source: https://github.com/dotnet/runtime/blob/354ec46a63440608bda18e2203bb5538e2f8eae6/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CryptographicOperations.cs
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        // NoOptimization because we want this method to be exactly as non-short-circuiting
        // as written.
        //
        // NoInlining because the NoOptimization would get lost if the method got inlined.

        if (left.Length != right.Length)
        {
            return false;
        }

        int length = left.Length;
        int accum = 0;

        for (int i = 0; i < length; i++)
        {
            accum |= left[i] - right[i];
        }

        return accum == 0;
    }
}

internal static class RandomNumberGenerator
{
    public static void Fill(Span<byte> buffer)
    {
        var bytes = new byte[buffer.Length];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        bytes.CopyTo(buffer);
    }
}