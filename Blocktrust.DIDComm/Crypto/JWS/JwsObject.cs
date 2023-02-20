namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using JWE;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

public class JwsObject
{
    public Dictionary<string, object> ProtectedHeader { get; }
    public Dictionary<string, object> UnprotectedHeader { get; }

    //unclear
    public string SigningInputString { get; }

    public JwsTokenState State { get; set; }

    //is a more complicated object, but a string does it for noew
    public JwsPayload Payload { get; set; }

    //gets set after the signing
    public List<JwsSignature> Signatures { get; set; }

    public JwsObject()
    {
    }

    public JwsObject(Dictionary<string, object> protectedHeader, Dictionary<string, object> unprotectedHeader, string payload)
    {
        ProtectedHeader = protectedHeader;
        UnprotectedHeader = unprotectedHeader;
        Payload = new JwsPayload(payload);
        State = JwsTokenState.Unsigned;
        Signatures = new List<JwsSignature>();
        var header = JsonSerializer.Serialize(protectedHeader, SerializationOptions.UnsafeRelaxedEscaping);
        var bytesHeader = Encoding.UTF8.GetBytes(header);
        var headerBase64 = Base64Url.Encode(bytesHeader);

        SigningInputString = $"{headerBase64}.{Payload.Base64}";
    }


    public void Sign(Jwk jwk)
    {
        if (State != JwsTokenState.Unsigned)
        {
            throw new Exception("JWS token is not in the correct state");
        }

        byte[] signature = default;
        var alg = Jws.GetJwsAlgorithmWrapper(jwk);
        var message = Encoding.UTF8.GetBytes(SigningInputString);
        switch (alg)
        {
            case JwsAlgorithm.ES256:
                signature = ECDSA.Sign(message, jwk);
                break;
            
            case JwsAlgorithm.ES256K:
                signature = ECDSA.Sign(message, jwk);
                break;

            case JwsAlgorithm.EdDSA:
                var signer = new Ed25519Signer();
                var privateKeyBytes = Base64Url.Decode(jwk.D);

                signer.Init(true, new Ed25519PrivateKeyParameters(privateKeyBytes, 0));
                signer.BlockUpdate(message, 0, message.Length);
                signature = signer.GenerateSignature();
                break;
        }


        Signatures.Add(new JwsSignature()
        {
            Payload = new JwsPayload(Payload.Base64, true),
            UnprotectedHeader = UnprotectedHeader,
            ProtectedHeader = ProtectedHeader,
            Signature = Base64Url.Encode(signature)
        });
    }


    public string Serialize()
    {
        var jwsObjectJson = new JwsObjectJson()
        {
            Payload = Payload.Base64,
            Signatures = Signatures.Select(p => new JwsSignatureJson(p)).ToList()
        };
        var s = JsonSerializer.Serialize(jwsObjectJson, SerializationOptions.UnsafeRelaxedEscaping);
        return s;
    }

    public static JwsObject Parse(Dictionary<string, object> rawMessage)
    {
        var payloadJsonElement = (JsonElement)rawMessage["payload"];
        var payload = payloadJsonElement.GetString()!;

        var signaturesJsonElement = (JsonElement)rawMessage["signatures"];
        var signaturesInJson = signaturesJsonElement.GetRawText();

        var signatures = JsonSerializer.Deserialize<List<JwsSignatureJson>>(signaturesInJson);
        return new JwsObject()
        {
            Signatures = signatures.Select(p => new JwsSignature(p, new JwsPayload(payload, true))).ToList(),
            Payload = new JwsPayload(payload, true),
            State = JwsTokenState.Signed,
        };
    }
}