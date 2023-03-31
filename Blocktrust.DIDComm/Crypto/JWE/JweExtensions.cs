namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Common.Algorithms;
using Common.Types;
using Exceptions;
using FluentResults;
using JWM;
using JWS;
using Keys;
using Message.Messages;
using Model.UnpackResultModels;
using Operations;
using ProtocolsRouting.ForwardMessages;
using Utils;

public class JweExtensions
{
    public static EncryptResult AuthEncrypt(string payload, AuthCryptAlg auth, Key from, List<Key> to)
    {
        string skid = from.Id;
        List<string> kids = to.Select(x => x.Id).OrderBy(x => x).ToList();
        //TODO unclear on what encodign to use
        var byteArray = Encoding.UTF8.GetBytes(from.Id);
        string apu = Base64Url.Encode(byteArray);
        string apv = DidUtils.CalculateApv(kids);

        (string alg, string enc) = (auth.CryptAlg) switch
        {
            AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW => (JweAlgorithmExtension.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512),
            _ => throw new ArgumentException("Invalid AuthCryptAlg value.")
        };

        var jweHeader = new JweHeader().Builder(alg, enc)
            .Typ(MessageTyp.Encrypted)
            .AgreementPartyVInfo(apv)
            .AgreementPartyUInfo(apu)
            .SenderKeyId(skid)
            .Build();

        Jwk sender = from.Jwk;
        List<(UnprotectedHeader, Jwk)> recipients = to.Select(x => (new UnprotectedHeader(new Dictionary<string, object>() { { "kid", x.Id } }), jwk: x.Jwk)).ToList();


        IJWEEncrypterMulti encryptor = (sender.Kty) switch
        {
            "EC" => new ECDH1PUEncrypterMulti(sender, recipients),
            "OKP" => new ECDH1PUX25519EncrypterMulti(sender, recipients),
            _ => throw new UnsupportedJwkException(sender.GetType().Name)
        };

        JweObject jweObject = new JweObject(jweHeader, payload);
        JweCryptoParts parts;
        try
        {
            parts = jweObject.Encrypt(encryptor);
        }
        catch (Exception e)
        {
            //Don't allow expections past this point
            throw;
        }

//TODO this is somewhat unpractical. The jweOBject was already created beforehand and could be reusied...

        var jweObjectJson = new JweObjectJson(
            header: Base64Url.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parts.JweHeader.Header, SerializationOptions.UnsafeRelaxedEscaping))),
            recipients: parts.Recipients,
            iv: parts.InitializationVector,
            cipherText: parts.CipherText,
            authTag: parts.AuthenticationTag
        );

        var serialized = JsonSerializer.Serialize<JweObjectJson>(jweObjectJson, SerializationOptions.UnsafeRelaxedEscaping);
        var ec = new EncryptResult(serialized, kids, from.Id);
        return ec;
    }

    public static EncryptResult AnonEncrypt(string payload, AnonCryptAlg anon, List<Key> to)
    {
        var kids = to.Select(key => key.Id).OrderBy(kid => kid).ToList();
        var apv = DidUtils.CalculateApv(kids);

        (string alg, string enc) = anon.CryptAlg switch
        {
            AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW => (JweAlgorithmExtension.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512),
            AnonCryptAlg.XC20P_ECDH_ES_A256KW => (JweAlgorithmExtension.ECDH_ES_A256KW, EncryptionMethod.XC20P),
            AnonCryptAlg.A256GCM_ECDH_ES_A256KW => (JweAlgorithmExtension.ECDH_ES_A256KW, EncryptionMethod.A256GCM),
            _ => throw new Exception("Unknown anonymous encryption algorithm"),
        };

        var jweHeader = new JweHeader().Builder(alg, enc)
            .AgreementPartyVInfo(apv)
            .Build();

        List<(UnprotectedHeader, Jwk)> recipients = to.Select(x => (new UnprotectedHeader(new Dictionary<string, object>() { { "kid", x.Id } }), jwk: x.Jwk)).ToList();

        IJWEEncrypterMulti encryptor = (recipients.First().Item2.Kty) switch
        {
            "EC" => new ECDHEncrypterMulti(recipients),
            "OKP" => new ECDHX25519EncrypterMulti(recipients),
            _ => throw new UnsupportedJwkException(nameof(recipients))
        };

        JweObject jweObject = new JweObject(jweHeader, payload);
        JweCryptoParts parts;
        try
        {
            parts = jweObject.Encrypt(encryptor);
        }
        catch (Exception e)
        {
            //Don't allow expections past this point
            throw;
        }

        var jweObjectJson = new JweObjectJson()
        {
            Header = Base64Url.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parts.JweHeader.Header, SerializationOptions.UnsafeRelaxedEscaping))),
            Recipients = parts.Recipients,
            Iv = parts.InitializationVector,
            CipherText = parts.CipherText,
            AuthTag = parts.AuthenticationTag,
        };

        var serialized = JsonSerializer.Serialize(jweObjectJson, SerializationOptions.UnsafeRelaxedEscaping);
        var ec = new EncryptResult(serialized, kids);
        return ec;
    }

    public static DecryptResult AuthDecrypt(JweObject jwe, bool decryptByAllKeys, Key from, List<Key> to)
    {
        if (decryptByAllKeys)
        {
            return AuthDecryptForAllKeys(jwe, from, to.ToList());
        }
        else
        {
            var result = AuthDecryptForOneKey(jwe, from, to);
            if (result == null)
            {
                throw new MalformedMessageException("Decrypt failed");
            }

            return result;
        }
    }

    public static DecryptResult AnonDecrypt(JweObject jwe, bool decryptByAllKeys, List<Key> to)
    {
        if (decryptByAllKeys)
        {
            return AnonDecryptForAllKeys(jwe, to.ToList());
        }
        else
        {
            var result = AnonDecryptForOneKey(jwe, to); //Where(x => x != null).FirstOrDefault();
            if (result == null)
            {
                throw new MalformedMessageException("Decrypt failed");
            }

            return result;
        }
    }


    private static DecryptResult AuthDecryptForOneKey(JweObject jwe, Key from, List<Key> to)
    {
        DecryptResult r = null;
        foreach (var key in to)
        {
            try
            {
                r = AuthDecryptForAllKeys(jwe, from, new List<Key> { key });
                if (r != null)
                {
                    break;
                }
            }
            catch (MalformedMessageException)
            {
                // skip and go to next key
                continue;
            }
        }

        return r;
    }

    private static DecryptResult AnonDecryptForOneKey(JweObject jwe, List<Key> to)
    {
        DecryptResult r = null;
        foreach (var key in to)
        {
            try
            {
                r = AnonDecryptForAllKeys(jwe, new List<Key> { key });
                if (r != null)
                {
                    break;
                }
            }
            catch (MalformedMessageException)
            {
                // skip and go to next key
                continue;
            }
        }


        return r;
    }

    private static DecryptResult AuthDecryptForAllKeys(JweObject jwe, Key from, List<Key> to)
    {
        var sender = from.Jwk;
        var recipients = new List<(UnprotectedHeader, Jwk)>();

        foreach (var key in to)
        {
            var unprotectedHeader = new UnprotectedHeader().Builder().KeyId(key.Id).Build();
            recipients.Add((unprotectedHeader, key.Jwk));
        }

        IJWEDecrypterMulti decryptor = (sender.Kty) switch
        {
            "EC" => new ECDH1PUDecrypterMulti(sender, recipients),
            "OKP" => new ECDH1PUX25519DecrypterMulti(sender, recipients),
            _ => throw new UnsupportedJwkException(sender.GetType().Name)
        };

        try
        {
            jwe.Decrypt(decryptor);
        }
        catch (Exception e)
        {
            throw new MalformedMessageException("Decrypt is failed:");
        }

        return new DecryptResult(jwe.Payload.JsonDictionary, to.Select(key => key.Id).ToList(), from.Id);
    }


    private static DecryptResult AnonDecryptForAllKeys(JweObject jwe, List<Key> to)
    {
        var recipients = new List<(UnprotectedHeader, Jwk)>();

        foreach (var key in to)
        {
            var unprotectedHeader = new UnprotectedHeader().Builder().KeyId(key.Id).Build();
            recipients.Add((unprotectedHeader, key.Jwk));
        }

        IJWEDecrypterMulti decryptor = (recipients.First().Item2.Kty) switch
        {
            "EC" => new ECDHDecrypterMulti(recipients),
            "OKP" => new X25519DecrypterMulti(recipients),
            _ => throw new UnsupportedJwkException(recipients.GetType().Name)
        };

        try
        {
            jwe.Decrypt(decryptor);
        }
        catch (Exception e)
        {
            //Don't allow expections past this point
            throw new MalformedMessageException("Decrypt is failed");
        }

        return new DecryptResult(jwe.Payload.JsonDictionary, to.Select(key => key.Id).ToList());
    }

    //
    //
    public static CryptAlg GetCryptoAlg(JweObject jwe)
    {
        var alg = jwe.GetHeaderAlgorithm();
        var enc = jwe.GetHeaderEncryption();

        if (alg == JweAlgorithmExtension.ECDH_ES_A256KW && enc == EncryptionMethod.A256CBC_HS512)
        {
            return new AnonCryptAlg(AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW);
        }
        else if (alg == JweAlgorithmExtension.ECDH_1PU_A256KW && enc == EncryptionMethod.A256CBC_HS512)
        {
            return new AuthCryptAlg(AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW);
        }
        else if (alg == JweAlgorithmExtension.ECDH_ES_A256KW && enc == EncryptionMethod.XC20P)
        {
            return new AnonCryptAlg(AnonCryptAlg.XC20P_ECDH_ES_A256KW);
        }
        else if (alg == JweAlgorithmExtension.ECDH_ES_A256KW && enc == EncryptionMethod.A256GCM)
        {
            return new AnonCryptAlg(AnonCryptAlg.A256GCM_ECDH_ES_A256KW);
        }
        else
        {
            throw new UnsupportedAlgorithmException($"{alg}+{enc}");
        }
    }

    // //TODO moved here. unclear if references are correct 
    public static async Task<(Result<Message>, Metadata)> Unpack(
        JweParseResult jweParseResult,
        RecipientKeySelector keySelector,
        bool expectDecryptByAllKeys,
        UnpackResultBuilder metadataUnpackResultBuilder,
        bool unwrapReWrappingForward
    )
    {
        CryptAlg alg = GetCryptoAlg(jweParseResult.Message);
        switch (alg)
        {
            case AuthCryptAlg:
                var authUnpackResult = await JweExtensions.AuthUnpack(
                    jweParseResult,
                    keySelector,
                    (AuthCryptAlg)alg,
                    expectDecryptByAllKeys,
                    metadataUnpackResultBuilder
                );
                //TODO?
                return ((authUnpackResult, null));
            case AnonCryptAlg:
                var AnonUnpackResult = await JweExtensions.AnonUnpack(
                    jweParseResult,
                    keySelector,
                    (AnonCryptAlg)alg,
                    expectDecryptByAllKeys,
                    metadataUnpackResultBuilder,
                    unwrapReWrappingForward
                );
                return (AnonUnpackResult, null);
                break;
        }

        return default;
    }


    private static async Task<Message> AuthUnpack(
        JweParseResult jweParseResult,
        RecipientKeySelector keySelector,
        AuthCryptAlg authCryptAlg,
        bool decryptByAllKeys,
        UnpackResultBuilder metadataUnpackResultBuilder
    )
    {
        //TODO this is all somewhat shitty. Should prefer a method
        //  //Same code as in AnonUpack
        var senderKeyId = (string)jweParseResult.Message.UnprotectedHeader.Header["skid"];
        if (senderKeyId is null)
        {
            throw new MalformedMessageException("The \"skid\" header must be present");
        }

        var apu = (string)jweParseResult.Message.UnprotectedHeader.Header["apu"];
        //TODO we need something like in the Kotlincode to directly decode to string
        //Since we have to implement Base64URl anyway in out code, we can do that
        var apuAsBytes = Base64Url.Decode(apu);
        var apuAsString = Encoding.UTF8.GetString(apuAsBytes);

        if (senderKeyId != null && apuAsString != senderKeyId)
        {
            throw new MalformedMessageException("apu is not equal to skid");
        }


        var recipientsList = jweParseResult.Message.Recipients?.Where(it => it?.UnprotectedHeader["kid"] != null)
                             ?? throw new MalformedMessageException("JWE Unprotected Per-Recipient header must be present");
        var kidList = recipientsList.Select(p => (string)p.UnprotectedHeader["kid"]).ToList();

        var apv = (string)jweParseResult.Message.UnprotectedHeader.Header["apv"];
        if (apv != null && apv != DidUtils.CalculateApv(kidList)
           )
        {
            throw new MalformedMessageException("apv is invalid");
        }

        var (from, to) = await keySelector.FindAuthCryptKeys(senderKeyId, kidList);
        var decrypted = AuthDecrypt(jweParseResult.Message, decryptByAllKeys, from, to);

        metadataUnpackResultBuilder
            .EncryptedTo(decrypted.ToKids)
            .EncryptedFrom(decrypted.FromKid)
            .EncAlgAuth(authCryptAlg)
            .Encrypted(true)
            .Authenticated(true);

        return JwmParseResult.Parse(decrypted.UnpackedMessage) switch
        {
            JwsParseResult jws => await Jws.Unpack(jws, keySelector, metadataUnpackResultBuilder),
            JwmParseResult jwm => await JwmExtensions.Unpack(jwm, keySelector, metadataUnpackResultBuilder),
            _ => throw new MalformedMessageException("Malformed Message")
        };
    }

    private static async Task<Result<Message>> AnonUnpack(
        JweParseResult jweParseResult,
        RecipientKeySelector keySelector,
        AnonCryptAlg anonCryptAlg,
        bool decryptByAllKeys,
        UnpackResultBuilder metadataUnpackResultBuilder,
        bool unwrapReWrappingForward
    )
    {
        //TODO this is all somewhat shitty. Should prefer a method
        //Same code as in AuthUnpack

        if (jweParseResult.Message.UnprotectedHeader.Header.ContainsKey("skid"))
        {
            var senderKeyId = (string)jweParseResult.Message.UnprotectedHeader.Header["skid"];
            if (senderKeyId is null)
            {
                throw new MalformedMessageException("The \"skid\" header must be present");
            }

            var apu = (string)jweParseResult.Message.UnprotectedHeader.Header["apu"];
            //TODO we need something like in the Kotlincode to directly decode to string
            //Since we have to implement Base64URl anyway in out code, we can do that
            var apuAsBytes = Base64Url.Decode(apu);
            var apuAsString = Encoding.UTF8.GetString(apuAsBytes);

            if (senderKeyId != null && apuAsString != senderKeyId)
            {
                throw new MalformedMessageException("apu is not equal to skid");
            }
        }

        var recipientsList = jweParseResult.Message.Recipients?.Where(it => it?.UnprotectedHeader["kid"] != null)
                             ?? throw new MalformedMessageException("JWE Unprotected Per-Recipient header must be present");
        var kidList = recipientsList.Select(p => (string)p.UnprotectedHeader["kid"]).ToList();

        if (jweParseResult.Message.UnprotectedHeader.Header.ContainsKey("apv"))
        {
            var apv = (string)jweParseResult.Message.UnprotectedHeader.Header["apv"];
            if (apv != null && apv != DidUtils.CalculateApv(kidList)
               )
            {
                throw new MalformedMessageException("apv is invalid");
            }
        }

        var to = (await keySelector.FindAnonCryptKeys(kidList)).ToList();
        var decrypted = AnonDecrypt(jweParseResult.Message, decryptByAllKeys, to);

        metadataUnpackResultBuilder
            .EncryptedTo(decrypted.ToKids)
            .AnonymousSender(true)
            .EncAlgAnon(anonCryptAlg)
            .Encrypted(true);

        var parseResult = JwmParseResult.Parse(decrypted.UnpackedMessage);

        if (unwrapReWrappingForward && parseResult is JwmParseResult)
        {
            var jwmMessage = (JwmParseResult)parseResult;
            if (jwmMessage.Message.Body.ContainsKey("next"))
            {
                var forwardMsg = ForwardMessage.FromMessage(jwmMessage.Message);
                if (await keySelector.HasKeysForForwardNext(forwardMsg.ForwardNext))
                {
                    metadataUnpackResultBuilder.ReWrappedInForward(true);
                    var unpackedResult = await Unpacker.Unpack(
                        forwardMsg.ForwardedMsg,
                        keySelector,
                        metadataUnpackResultBuilder,
                        decryptByAllKeys,
                        unwrapReWrappingForward
                    );

                    return unpackedResult;
                }
            }
        }

        return parseResult switch
        {
            JweParseResult jwe => await JweExtensions.AnonAuthUnpack(jwe, keySelector, decryptByAllKeys, metadataUnpackResultBuilder),
            JwsParseResult jws => await Jws.Unpack(jws, keySelector, metadataUnpackResultBuilder),
            JwmParseResult jwm => await JwmExtensions.Unpack(jwm, keySelector, metadataUnpackResultBuilder),
            _ => throw new MalformedMessageException("Malformed Message")
        };
    }

    private static async Task<Message> AnonAuthUnpack(JweParseResult jwe, RecipientKeySelector keySelector, bool decryptByAllKeys, UnpackResultBuilder metadataUnpackResultBuilder)
    {
        var alg = JweExtensions.GetCryptoAlg(jwe.Message);
        return alg switch
        {
            AuthCryptAlg authCryptAlg => await AuthUnpack(jwe, keySelector, authCryptAlg, decryptByAllKeys, metadataUnpackResultBuilder),
            _ => throw new MalformedMessageException("Malformed Message")
        };
    }
}