# Hybrid ML-KEM TLS qualification

Hybrid TLS capability is supplied by the application's operating system and native TLS stack, not by the `Azure.Security.ConfidentialLedger` package. Do not describe the package as supporting PQ TLS without naming a qualified runtime and operating system.

The manual live qualification prints the .NET, OS, and TLS-backend inventory; forces `X25519MLKEM768` with an external OpenSSL probe; runs an unforced OpenSSL handshake separately; and completes a ledger-certificate-chain-validated `GetEnclaveQuotesAsync` SDK request. The OpenSSL executable and the native library loaded by .NET can differ. This proves endpoint/runtime capability plus SDK compatibility, but it does not prove that the .NET SDK request negotiated ML-KEM. Packet capture or server-side CCF telemetry correlated to the SDK request is required for that claim.

```powershell
$env:AZURE_TEST_MODE = "Live"
dotnet test sdk/confidentialledger/Azure.Security.ConfidentialLedger/tests/Azure.Security.ConfidentialLedger.Tests.csproj `
  -f net10.0 `
  --filter "TestCategory=Manually&FullyQualifiedName~HybridMlKemTlsQualificationTests" `
  --logger "console;verbosity=detailed"
```

Set `CONFIDENTIALLEDGER_OPENSSL_PATH` when the qualifying OpenSSL executable is not on `PATH`.

## Support matrix

| Runtime and OS | Native TLS provider | Forced external probe | SDK negotiated group | SDK request | Status |
| --- | --- | --- | --- | --- | --- |
| .NET 10.0.4 / Ubuntu 24.04 WSL2 | OpenSSL 3.0.13 | Failed: group unavailable | Not tested | Not run with hybrid evidence | Unsupported |
| .NET 10 / Azure Linux 3 with SCOSSL 1.10 | OpenSSL 3.3.7 + SymCrypt provider | Pending | Requires packet/server telemetry | Pending | Not qualified |
| .NET 10 / Linux with OpenSSL 3.5+ | OpenSSL | Pending | Requires packet/server telemetry | Pending | Not qualified |
| .NET 10 / supported Windows build | Schannel | No managed forced-group control | Requires ETW/server telemetry | Pending | Not qualified |

Classical fallback must remain enabled until every supported runtime row passes or is explicitly documented as an exception.