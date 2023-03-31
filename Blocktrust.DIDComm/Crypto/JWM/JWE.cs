namespace Blocktrust.DIDComm.Crypto.JWM;

using System.Text.Json;
using Exceptions;
using JWE;

public sealed class JweParseResult : ParseResult
{
    public readonly JweObject Message;

    public JweParseResult(Dictionary<string, object?> rawMessage)
    {
        try
        {
            var jwe = new JweObject();
            if (rawMessage.ContainsKey("protected"))
            {
                var protectedHeader = rawMessage["protected"];
                jwe.UnprotectedHeader = JweHeader.Parse(protectedHeader.ToString());
            }
            else
            {
                throw new ArgumentException("The header must not be null");
            }

            if (rawMessage.ContainsKey("ciphertext"))
            {
                var ciphertext = (JsonElement)rawMessage["ciphertext"];
                //TODO do i have to use jsonelement here again?
                jwe.CipherText = (string)ciphertext.GetString();
            }
            else
            {
                throw new ArgumentException("The ciphertext must not be null");
            }

            if (rawMessage.ContainsKey("tag"))
            {
                var tag = (JsonElement)rawMessage["tag"];

                jwe.AuthTag = (string)tag.GetString();
            }

            if (rawMessage.ContainsKey("iv"))
            {
                var iv = (JsonElement)rawMessage["iv"];
                jwe.Iv = (string)iv.GetString();
            }

            if (rawMessage.ContainsKey("recipients"))
            {
                //Refactor and move elsewhere
                jwe.Recipients = new List<JweRecipientCustom>();
                var recipientsRaw = rawMessage["recipients"];
                var recipientsAsJsonElement = (JsonElement)recipientsRaw;
                if (recipientsAsJsonElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var recipientItem in recipientsAsJsonElement.EnumerateArray())
                    {
                        if (recipientItem.ValueKind == JsonValueKind.Object)
                        {
                            string encryptedKey = default;
                            Dictionary<string, object> header = new Dictionary<string, object>();
                            foreach (var obj in recipientItem.EnumerateObject())
                            {
                                if (obj.Name == "encrypted_key")
                                {
                                    var encryptedKeyString = obj.Value.GetString();
                                    encryptedKey = encryptedKeyString;
                                }

                                if (obj.Name == "header")
                                {
                                    if (obj.Value.ValueKind == JsonValueKind.Object)
                                    {
                                        foreach (var objItem in obj.Value.EnumerateObject())
                                        {
                                            header.Add(objItem.Name, objItem.Value.GetString());
                                        }
                                    }
                                }
                            }

                            var r = new JweRecipientCustom(header, encryptedKey);
                            jwe.Recipients.Add(r);
                        }
                    }
                }
                else
                {
                    throw new NotImplementedException();
                }
            }

            // TODO the jose-jwt might be supporting parsing to a jweToken
            // NOW transform the JWE token to the JWE object??
            this.Message = jwe;
            // TODO actually not so sure if this is correct here. but i need it later
            this.Message.State = JweTokenState.Encrypted;
        }
        catch (Exception e)
        {
            throw new MalformedMessageException(e.Message);
        }
    }
}