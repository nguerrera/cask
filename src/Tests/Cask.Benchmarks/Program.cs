// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if RELEASE
using BenchmarkDotNet.Running;
#endif

using CommonAnnotatedSecurityKeys.Benchmarks;

#if DEBUG
new CompareHashedSignatureBenchmarks().UseCompareHash();
#endif

#if RELEASE
/* To run this benchmark, navigate to the benchmark source directory
 * and use the following command:
 * 
 * dotnet run -c Release --framework net8.0 Cask.Benchmarks.csproj
 */
BenchmarkRunner.Run([
    //typeof(IsCaskBenchmarks),
    typeof(CompareHashedSignatureBenchmarks),
 ]);
#endif
