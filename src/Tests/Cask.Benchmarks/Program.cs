// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/*
 * To run these benchmarks, navigate to the benchmark source directory and use
 * the following command:
 *
 *   dotnet run -c Release -f net8.0
 *
 * You can also run on .NET Framework:
 *
 *   dotnet run -c Release -f net472
 *
 * To debug the benchmarks, you can set this project as the startup project in
 * Debug configuration. Each benchmark will be run once without measuring
 * anything.
 *
 * You can also pass additional options to BenchmarkDotNet on the command line
 * using the `--` separator:
 *
 *   dotnet run -c Release -f net8.0 -- --help
 *
 * To run a subset of benchmarks, you can pass a glob pattern to --filter:
 *
 *   dotnet run -c Release --framework net8.0 -- --filter *MyBenchmark*
 */

using System.Reflection;

using BenchmarkDotNet.Running;

using CommonAnnotatedSecurityKeys.Benchmarks;

bool debug = false;

#if DEBUG 
debug = true;
#else
debug = System.Diagnostics.Debugger.IsAttached;
#endif

if (debug)
{
    DebugBenchmarkRunner.Run();
    return;
}

BenchmarkRunner.Run(Assembly.GetExecutingAssembly(), config: null, args);
