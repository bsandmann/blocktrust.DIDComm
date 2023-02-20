namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

using Common.Algorithms;
using Model.UnpackResultModels;

public class JWSFixture
{
    public static List<JWSTestVector> TEST_VECTORS = new List<JWSTestVector>
    {
        new JWSTestVector(
            from: "did:example:alice#key-1",
            expected: """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                             "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                             "header":{
                                "kid":"did:example:alice#key-1"
                             }
                          }
                       ]
                    }
                """.Trim(),
            expectedMetadata: new Metadata(
                encrypted: false,
                authenticated: true,
                nonRepudiation: true,
                signFrom: "did:example:alice#key-1",
                signAlg: SignAlg.Ed25519
            )
        ),
        new JWSTestVector(
            from:  "did:example:alice#key-2",
            expected: """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                             "signature":"gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                             "header":{
                                "kid":"did:example:alice#key-2"
                             }
                          }
                       ]
                    }
                """.Trim(),
            expectedMetadata: new Metadata(
                encrypted: false,
                authenticated: true,
                nonRepudiation: true,
                signFrom: "did:example:alice#key-2",
                signAlg: SignAlg.Es256
            )
        ),
        new JWSTestVector(
            from:  "did:example:alice#key-3",
            expected: """
                    {
                       "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
                       "signatures":[
                          {
                             "protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                             "signature":"EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
                             "header":{
                                "kid":"did:example:alice#key-3"
                             }
                          }
                       ]
                    }
                """.Trim(),
            expectedMetadata: new Metadata(
                encrypted: false,
                authenticated: true,
                nonRepudiation: true,
                signFrom:  "did:example:alice#key-3",
                signAlg:SignAlg.Es256K
            )
        ),
    }; 
}