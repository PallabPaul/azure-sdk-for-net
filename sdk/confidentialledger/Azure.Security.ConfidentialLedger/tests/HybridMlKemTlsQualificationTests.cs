// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Azure.Core.TestFramework;
using Azure.Security.ConfidentialLedger.Certificate;
using NUnit.Framework;

namespace Azure.Security.ConfidentialLedger.Tests
{
    [LiveOnly]
    [Category("Manually")]
    [NonParallelizable]
    public class HybridMlKemTlsQualificationTests : RecordedTestBase<ConfidentialLedgerEnvironment>
    {
        private const string RequiredHybridGroup = "X25519MLKEM768";

        public HybridMlKemTlsQualificationTests(bool isAsync)
            : base(isAsync)
        {
        }

        [Test]
        public async Task QualifyHybridAndDefaultTlsWithSdkRequest()
        {
            string openssl = Environment.GetEnvironmentVariable("CONFIDENTIALLEDGER_OPENSSL_PATH") ?? "openssl";
            TestContext.Progress.WriteLine($"Framework: {RuntimeInformation.FrameworkDescription}");
            TestContext.Progress.WriteLine($"Runtime version: {Environment.Version}");
            TestContext.Progress.WriteLine($"OS: {RuntimeInformation.OSDescription}");
            TestContext.Progress.WriteLine($"Architecture: {RuntimeInformation.OSArchitecture}/{RuntimeInformation.ProcessArchitecture}");
            TestContext.Progress.WriteLine($"TLS backend: {GetTlsBackendDescription()}");
            TestContext.Progress.WriteLine(await RunAsync("dotnet", "--info").ConfigureAwait(false));
            TestContext.Progress.WriteLine(await RunAsync(openssl, "version -a").ConfigureAwait(false));
            TestContext.Progress.WriteLine(await RunAsync(openssl, "list -providers").ConfigureAwait(false));

            var identityClient = new ConfidentialLedgerCertificateClient(TestEnvironment.ConfidentialLedgerIdentityUrl);
            var serviceCert = ConfidentialLedgerClient.GetIdentityServerTlsCert(
                TestEnvironment.ConfidentialLedgerUrl,
                new ConfidentialLedgerCertificateClientOptions(),
                identityClient);

            string certPath = Path.GetTempFileName();
            try
            {
                File.WriteAllText(certPath, serviceCert.PEM);
                string forcedOutput = await ProbeAsync(openssl, certPath, RequiredHybridGroup).ConfigureAwait(false);
                Assert.That(forcedOutput, Does.Contain("Verification: OK").Or.Contain("Verify return code: 0 (ok)"));
                TestContext.Progress.WriteLine($"Forced {RequiredHybridGroup} handshake succeeded.\n{forcedOutput}");

                string defaultOutput = await ProbeAsync(openssl, certPath, null).ConfigureAwait(false);
                Assert.That(defaultOutput, Does.Contain("Verification: OK").Or.Contain("Verify return code: 0 (ok)"));
                TestContext.Progress.WriteLine($"Default handshake (not forced):\n{defaultOutput}");

                var client = new ConfidentialLedgerClient(
                    TestEnvironment.ConfidentialLedgerUrl,
                    TestEnvironment.Credential,
                    clientCertificate: null,
                    identityServiceCert: serviceCert.Cert);
                var response = await client.GetEnclaveQuotesAsync(new()).ConfigureAwait(false);
                Assert.AreEqual((int)HttpStatusCode.OK, response.Status);
            }
            finally
            {
                File.Delete(certPath);
            }
        }

        private async Task<string> ProbeAsync(string openssl, string certPath, string group)
        {
            Uri endpoint = TestEnvironment.ConfidentialLedgerUrl;
            string groupArgument = group == null ? string.Empty : $" -groups {group}";
            string arguments = $"s_client -connect {endpoint.Host}:{endpoint.Port} -servername {endpoint.Host} " +
                $"-verify_hostname {endpoint.Host} -CAfile \"{certPath}\" -verify_return_error -tls1_3 -brief{groupArgument}";
            return await RunAsync(openssl, arguments).ConfigureAwait(false);
        }

        private static string GetTlsBackendDescription()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "Schannel (version follows the Windows build above)";
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "platform OpenSSL";
            }
            return "platform TLS provider (not qualified by this test)";
        }

        private static async Task<string> RunAsync(string fileName, string arguments)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.StandardInput.Close();
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30000))
            {
                process.Kill();
                Assert.Fail($"Timed out running {fileName} {arguments}");
            }
            string output = (await stdout.ConfigureAwait(false)) + (await stderr.ConfigureAwait(false));
            Assert.AreEqual(0, process.ExitCode, output);
            return output;
        }
    }
}
