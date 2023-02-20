﻿namespace Blocktrust.DIDComm.Tests.TestData.Messages;

using Fixtures;
using Message.Attachments;
using Message.Messages;

public class DIDCommMessages
{
    public static Message AttachmentMulti1msg()
    {
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy(
            attachments: new List<Attachment>
            {
                new AttachmentBuilder(
                    id: "23",
                    data: new Json(
                        json: new Dictionary<string, object>
                        {
                            { "foo", "bar" },
                            { "links", new List<int> { 2, 3 } }
                        }
                    )
                ).Build(),
                new AttachmentBuilder(id: "24", data: Base64.Parse(new Dictionary<string, object> { { "base64", "qwerty" } })).Build(),
                new AttachmentBuilder(
                    id: "25",
                    data: new Links(
                        linksString : new List<string> { "1", "2", "3" },
                        hash: "qwerty"
                    )
                ).Build()
            }
        );
        return msg;
    }

    public static Message AttachmentJsonMsg()
    {
        var msg = JWMFixture.PLAINTEXT_MESSAGE.Copy(
            attachments: new List<Attachment>
            {
                new AttachmentBuilder(
                    id: "23",
                    data: new Json(json: new Dictionary<string, object> { { "foo", "bar" }, { "links", "[2, 3]" } })
                ).Build()
            }
        );
        return msg;
    }
}