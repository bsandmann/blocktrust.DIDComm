# blocktrust.DIDComm

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## .net implementation of the [DIDcomm Messaging v2 specification](https://identity.foundation/didcomm-messaging/spec/)
based on the SICPA DIDComm kotlin codebase for the JVM ([see SICPA](https://github.com/sicpa-dlab/didcomm-jvm))

## Dependencies:
- [blocktrust.Core](https://github.com/bsandmann/blocktrust.Core) for common methods like VarInt, MultiCodec, Base64, etc
- [SimleBase](https://github.com/ssg/SimpleBase) for Base58 encoding
- [BouncyCastle](https://www.bouncycastle.org/csharp/) for cryptographic operations (https://www.nuget.org/packages/Portable.BouncyCastle)

## Motivation
The goal was to create a DIDComm library for the .net ecosystem which is lightweight and could also be used in the browser (Blazor). The code itself is a direct port of the SICPA DIDComm implementation for the JVM, with all its Features and Tests. For cryptographic operations this library currently relies on bouncycastle, but with future versions, this library will be agnostic to the specific crypto library used.
The main challenge of the port was, that there is currently no JOSE library out there that supports ED25519 and X25519, while being agnostic to the crypto implementation itself. Since the goal was to use this library in Blazor, dependencies to windows system.security.cryptography where not acceptable, this this wouldn’t run in Blazor. Additionally, dependencies to microsoft.identitymodel were also not acceptable. This forced this library not only to be a DIDComm v2 implementation but also model the necessary parts of the JOSE family from token creation to validation.
## Current state and further development
The library itself can be used and should be robust enough for non-production use cases. It passes all the over 2000 tests which have also been ported from the Kotlin codebase over to net. The API is nearly identical to the JVM one, but will most likely change a bit over time due to refactorings.
The project is primarily meant to be used within the blocktrust infrastructure to build the blocktrust identity wallet and other related products. This leads to the fact, that some functionality, types and common classes have been moved to the blocktrust. Core library to reduce code duplication. Over time, additional parts of the library will also be moved to this or other blocktrust libraries.
Many parts of this library are still work in progress: this is especially true for everything around the JOSE implementations (JWE,JWM, …). The amount of refactoring and code improvements which can be done is still massive, but should be manageable since the code has a pretty good test coverage. Nonetheless there still be might be dragons around here: You have been warned.
## Usage
The api is nearly identical to the JVM implementation [see here](https://github.com/sicpa-dlab/didcomm-jvm) and covers all the same features, but offers also support for secp256k1 (which is not available on newer versions of the JVM).
