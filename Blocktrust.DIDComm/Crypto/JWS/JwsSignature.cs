namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Common.Algorithms;
using Exceptions;
using JWE;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

public class JwsSignature
{
    public JwsSignature()
    {
    }

    public JwsSignature(JwsSignatureJson jwsSignatureJson, JwsPayload jwsPayload)
    {
        Payload = jwsPayload;
        UnprotectedHeader = jwsSignatureJson.Header;
        Signature = jwsSignatureJson.Signature;
        var headerBase64 = jwsSignatureJson.Protected;
        try
        {
            var headerBytes = Base64Url.Decode(headerBase64);
            var headerString = Encoding.UTF8.GetString(headerBytes);
            ProtectedHeader = JsonSerializer.Deserialize<Dictionary<string, object>>(headerString);
        }
        catch (Exception e)
        {
            throw new MalformedMessageException("Invalid signature");
        }
    }

    public JwsPayload Payload { get; set; }
    public Dictionary<string, object> ProtectedHeader { get; set; }
    public Dictionary<string, object> UnprotectedHeader { get; set; }
    public string Signature { get; set; }


    public bool Verify(Jwk jwk, SignAlg signAlg)
    {
        var messageQuestionmark = new JwsObject(ProtectedHeader, UnprotectedHeader, Payload.JsonString);
        var message = Encoding.UTF8.GetBytes(messageQuestionmark.SigningInputString);
        var signature = Base64Url.Decode(Signature);

        switch (signAlg)
        {
            case SignAlg.Es256:
                return ECDSA.Verify(message, jwk, signature);

            case SignAlg.Es256K:
                return ECDSA.Verify(message, jwk, signature);

                break;
            case SignAlg.Ed25519:
//TODO refactor into some other file
                var publicKeyBytes = Base64Url.Decode(jwk.X);
                var validator = new Ed25519Signer();
                validator.Init(false, new Ed25519PublicKeyParameters(publicKeyBytes, 0));

                validator.BlockUpdate(message, 0, message.Length);

                bool isValidSignature = validator.VerifySignature(signature);
                return isValidSignature;
                break;
            default:
                throw new NotImplementedException();
        }
    }
}