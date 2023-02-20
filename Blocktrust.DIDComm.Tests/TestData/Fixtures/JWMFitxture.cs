namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

using Message.FromPriors;
using Message.Messages;

public class JWMFixture
{
    public static readonly string ALICE_DID = "did:example:alice";
    public static readonly string BOB_DID = "did:example:bob";
    public static readonly string CHARLIE_DID = "did:example:charlie";
    public static readonly string NONA_DID = "did:example:nona";
    public static readonly string ELLIE_DID = "did:example:ellie";

    private const string ID = "1234567890";
    private const string TYPE = "http://example.com/protocols/lets_do_lunch/1.0/proposal";
    private static readonly Dictionary<string, object> BODY = new Dictionary<string, object> { { "messagespecificattribute", "and its value" } };

    public static readonly Message PLAINTEXT_MESSAGE = new MessageBuilder(ID, BODY, TYPE)
        .from(ALICE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_FROM_PRIOR_MINIMAL = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: ALICE_DID, sub: CHARLIE_DID).Build()
        )
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_FROM_PRIOR = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: ALICE_DID, sub: CHARLIE_DID)
                .Aud("123")
                .Exp(1234)
                .Nbf(12345)
                .Iat(123456)
                .Jti("dfg")
                .Build()
        )
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_ISS = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: "invalid", sub: CHARLIE_DID).Build()
        )
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_SUB = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: ALICE_DID, sub: "invalid").Build()
        )
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_EQUAL_ISS_AND_SUB = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: CHARLIE_DID, sub: CHARLIE_DID).Build()
        )
        .build();

    public static readonly Message PLAINTEXT_MESSAGE_MISMATCHED_FROM_PRIOR_SUB = new MessageBuilder(ID, BODY, TYPE)
        .from(CHARLIE_DID)
        .to(new List<string> { BOB_DID })
        .createdTime(1516269022)
        .expiresTime(1516385931)
        .fromPrior(
            FromPrior.Builder(iss: ALICE_DID, sub: ELLIE_DID).Build()
        )
        .build();

    public static readonly List<Message> INVALID_FROM_PRIOR_PLAINTEXT_MESSAGES = new List<Message>
    {
        PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_ISS,
        PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_SUB,
        PLAINTEXT_MESSAGE_INVALID_FROM_PRIOR_EQUAL_ISS_AND_SUB,
        PLAINTEXT_MESSAGE_MISMATCHED_FROM_PRIOR_SUB
    };

    public static readonly string PACKED_MESSAGE_WITHOUT_BODY = """
            {
               "id":"1234567890",
               "typ":"application/didcomm-plain+json",
               "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
               "from":"did:example:alice",
               "to":[
                  "did:example:bob"
               ],
               "created_time":1516269022,
               "expires_time":1516385931
            }
        """;

    public static readonly string PACKED_MESSAGE_FROM_PRIOR = """
            {
                "id":"1234567890",
                "typ":"application/didcomm-plain+json",
                "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                "from":"did:example:charlie",
                "to":[
                    "did:example:bob"
                ],
                "created_time":1516269022,
                "expires_time":1516385931,
                "from_prior":"eyJraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwiYXVkIjoiMTIzIiwibmJmIjoxMjM0NSwiaXNzIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJleHAiOjEyMzQsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.R-6-uklPRTcVSIQqjHdELkpjVEG8n4r0IHr9llP9KNdvneOW4x94liEINtcCn2OM93pOweD1MsmA9L3oPfIIDA",
                "body": {
                    "messagespecificattribute":"and its value"
                }
            }
        """;

    public static readonly List<WrongMessage> WRONG_FROM_PRIOR_PACKED_MESSAGES = new List<WrongMessage>
        ()
        {
            new WrongMessage(
                """
                    {
                        "id":"1234567890",
                        "typ":"application/didcomm-plain+json",
                        "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                        "from":"did:example:charlie",
                        "to":[
                            "did:example:bob"
                        ],
                        "created_time":1516269022,
                        "expires_time":1516385931,
                        "from_prior":"invalid",
                        "body": {
                            "messagespecificattribute":"and its value"
                        }
                    }
                """,
                "JWT cannot be deserialized"
            ),
            new WrongMessage(
                """
                    {
                        "id":"1234567890",
                        "typ":"application/didcomm-plain+json",
                        "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                        "from":"did:example:charlie",
                        "to":[
                            "did:example:bob"
                        ],
                        "created_time":1516269022,
                        "expires_time":1516385931,
                        "from_prior":"eyJraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwiYXVkIjoiMTIzIiwibmJmIjoxMjM0NSwiaXNzIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJleHAiOjEyMzQsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.R-6-uklPRTcVSIQqjHdELkpjVEG8n4r0IHr9llP9KNdvneOW4x94liEINtcCn2OM93pOweD1MsmA9L3oPfIID",
                        "body": {
                            "messagespecificattribute":"and its value"
                        }
                    }
                """,
                "JWT has an invalid signature"
            )
        };

    public static readonly List<CorrectAttachment> CORRECT_ATTACHMENTS = new List<CorrectAttachment>
        ()
        {
            new CorrectAttachment(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }]
                     }
                """,
                new List<ExpectedAttachmentData>()
                {
                    new ExpectedAttachmentData(isLinks: true)
                }
            ),
            new CorrectAttachment(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "base64": "qwerty"
                            }
                       }]
                     }
                """,
                new List<ExpectedAttachmentData>()
                {
                    new ExpectedAttachmentData(isBase64: true)
                }
            ),
            new CorrectAttachment(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "json": {
                                    "foo": "bar",
                                    "links": [2, 3]
                                }
                            }
                       }]
                     }
                """,
                new List<ExpectedAttachmentData>()
                {
                    new ExpectedAttachmentData(isJson: true)
                }
            ),
            new CorrectAttachment(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{
                          
                       },
                       "attachments":[
                          {
                             "id":"23",
                             "data":{
                                "json":{
                                   "foo":"bar",
                                   "links":[
                                      2,
                                      3
                                   ]
                                }
                             }
                          },
                          {
                             "id":"23",
                             "data":{
                                "base64":"qwerty"
                             }
                          },
                          {
                             "id":"23",
                             "data":{
                                "links":[
                                   "1",
                                   "2",
                                   "3"
                                ],
                                "hash":"qwerty"
                             }
                          }
                       ]
                    }
                """,
                new List<ExpectedAttachmentData>()
                {
                    new ExpectedAttachmentData(isJson: true),
                    new ExpectedAttachmentData(isBase64: true),
                    new ExpectedAttachmentData(isLinks: true)
                }
            ),
            new CorrectAttachment(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }, { 
                            "id": "23",
                            "data": {
                                "base64": "qwerty"
                            }
                       }, { 
                            "id": "23",
                            "data": {
                                "links": ["1", "2", "3"],
                                "hash": "qwerty"
                            }
                       }]
                     }
                """,
                new List<ExpectedAttachmentData>()
                {
                    new ExpectedAttachmentData(isLinks: true),
                    new ExpectedAttachmentData(isBase64: true),
                    new ExpectedAttachmentData(isLinks: true)
                }
            ),
        };

    public static readonly List<WrongMessage> WRONG_ATTACHMENTS = new List<WrongMessage>
        ()
        {
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{}]
                     }
                """,
                "The header \"id\" is missing"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23"
                       }]
                     }
                """,
                "The header \"data\" is missing"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {}
                       }]
                     }
                """,
                "Unknown attachment data"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{ 
                            "id": "23",
                            "data": {
                                "links": ["231", "212"]
                            }
                       }]
                     }
                """,
                "The header \"hash\" is missing"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": "131"
                     }
                """,
                "The expected type of header 'attachments' is 'List'. Got 'String'"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [2131]
                     }
                """,
                "The expected type of header 'attachments' is 'List'. Got 'Number'"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": 2 
                       }]
                     }
                """,
                "The expected type of header 'id' is 'String'. Got 'Number'"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": "1",
                           "data": null
                       }]
                     }
                """,
                "The header \"data\" is missing"
            ),
            new WrongMessage(
                """
                    {
                       "id":"1234567890",
                       "typ":"application/didcomm-plain+json",
                       "type":"http://example.com/protocols/lets_do_lunch/1.0/proposal",
                       "body":{},
                       "attachments": [{
                           "id": "1",
                           "data": "null"
                       }]
                     }
                """,
                "The expected type of header 'data' is 'Dictionary'. Got 'String'"
            ),
        };
}