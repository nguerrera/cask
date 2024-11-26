// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

namespace CommonAnnotatedSecurityKeys.Cli;

public class GenerateCommand
{
    private readonly string MicrosoftTenantId = new Guid("782ef2bb-3056-4438-946d-395022a4a19f").ToString();

    internal int Run(GenerateOptions options)
    {
        byte[] derivationInput = Encoding.UTF8.GetBytes(nameof(derivationInput));

        string cloudText = "AC";
        string region = EncodeForIdentifiableKey("westus");
        string tenant = EncodeForIdentifiableKey(MicrosoftTenantId);
        string providerReserved = "AAAA";
        byte[] reserved = Convert.FromBase64String($"{cloudText}{region}{tenant}{providerReserved}");

        byte[] providerSignature = UrlSafeBase64.ConvertFromString(options.FixedSignature);

        for (int i = 0; i < options.Count; i++)
        {

            byte[] keyBytes = Cask.GenerateKeyBytes(providerSignature,
                                                   "99",
                                                   reserved,
                                                   secretEntropyInBytes: options.SecretEntropyInBytes);


            string key = UrlSafeBase64.ConvertToString(keyBytes);

            string validity = Cask.IsCask(key) ? "Valid Key   " : "INVALID KEY ";
            Console.WriteLine($"{validity}: {key}");

            keyBytes = UrlSafeBase64.ConvertFromString(key);
            string hash = Cask.GenerateHash(derivationInput, keyBytes, options.SecretEntropyInBytes);

            validity = Cask.IsCask(hash) ? "Valid Hash  " : "INVALID HASH";
            Console.WriteLine($"{validity}: {hash}");
        }

        return 0;
    }

    public static string EncodeForIdentifiableKey(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "AAAAA";
        }

        byte[] hashed = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return UrlSafeBase64.ConvertToString(hashed).Substring(0, 5);
    }
}