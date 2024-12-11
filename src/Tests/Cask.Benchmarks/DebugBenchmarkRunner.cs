// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Reflection;

using BenchmarkDotNet.Attributes;

namespace CommonAnnotatedSecurityKeys.Benchmarks;

internal static class DebugBenchmarkRunner
{
    private const int Iterations = 10;

    public static void Run()
    {
        Console.WriteLine("WARNING: Running in debug build or with debugger attached.");
        Console.WriteLine("Each benchmark will be run a few times without measuring anything.");

        for (int i = 0; i < Iterations; i++)
        {
            foreach (Type type in Assembly.GetExecutingAssembly().GetTypes())
            {
                if (type.IsAbstract || type.IsGenericType || type.Namespace != typeof(DebugBenchmarkRunner).Namespace)
                {
                    continue;
                }

                object instance = Activator.CreateInstance(type)!;
                foreach (MethodInfo method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (method.IsDefined(typeof(BenchmarkAttribute)))
                    {
                        Console.WriteLine($"Running {type.Name}.{method.Name}...");
                        method.Invoke(instance, null);
                    }
                }
            }
        }
    }
}
