namespace Blocktrust.DIDComm.Crypto.JWS;

using System.Text.Json;
using Common.Algorithms;
using Common.Types;
using Exceptions;
using JWE;
using JWM;
using Keys;
using Message.Messages;
using Model.UnpackResultModels;

public class Jws
{
    public static string Sign(string payload, Key key)
    {
        var jwk = key.Jwk;
        var alg = GetJwsAlgorithmWrapper(jwk);

        string token = String.Empty;
        try
        {
            // ENsure surrport for signing 
            var protectedHeader = new JwsHeader().Builder(alg, typ: MessageTyp.Signed).Build();
            //thats some kind of trash
            var unprotectedHeaderDictionary = new Dictionary<string, object>();
            unprotectedHeaderDictionary.Add("kid", key.Id);
            var unprotectedHeader = new UnprotectedHeader(unprotectedHeaderDictionary);

            var jwsObject = new JwsObject(protectedHeader, unprotectedHeaderDictionary, payload);
            //TODO this code is more or less equicalent to jwtExtensions. understand why
            switch (alg)
            {
                case JwsAlgorithm.ES256:
                    jwsObject.Sign(key.Jwk);
                    return jwsObject.Serialize();

                    break;
                case JwsAlgorithm.EdDSA:
                    jwsObject.Sign(key.Jwk);
                    return jwsObject.Serialize();
                    break;
                case JwsAlgorithm.ES256K:
                    jwsObject.Sign(key.Jwk);
                    return jwsObject.Serialize();
                default:
                    throw new NotImplementedException();
                // throw new UnsupportedAlgorithm(alg.Name);
            }
        }
        catch (Exception e)
        {
            throw new Exception("Unsupported algorithm");
        }
    }


    static void Verify(JwsSignature signature, SignAlg signAlg, Key key)
    {
        var jwk = key.Jwk;

        try
        {
            switch (signAlg)
            {
                case SignAlg.Es256:
                    // throw new NotSupportedException("bla");
                    // verifier = new ECDSAVerifier(jwk.AsKey<ECKey>());
                    break;
                case SignAlg.Es256K:
                    // throw new NotSupportedException("bla");
                    // verifier = new ECDSAVerifier(jwk.AsKey<ECKey>());
                    break;
                case SignAlg.Ed25519:
                    //ahhhhhh no clue. That is correct 

                    break;
                default:
                    throw new UnsupportedAlgorithmException(signAlg.ToString());
            }

            if (!signature.Verify(jwk, signAlg))
            {
                throw new MalformedMessageException("Invalid signature");
            }
        }
        catch (Exception e)
        {
            throw new DidCommException("JWS signature cannot be verified", e);
        }
    }

    //TODO the same code exists in the JWTExtensions class?!
    public static SignAlg GetCryptoAlg(JwsSignature signature)
    {
        var alg = signature.ProtectedHeader["alg"].ToString();
        switch (alg)
        {
            //TODO this tring comparision is really bad and already caused problems.
            //Please parse and then compare
            case "ES256":
                return SignAlg.Es256;
            case "ES256K":
                return SignAlg.Es256K;
            case "EdDSA":
                return SignAlg.Ed25519;
            default:
                throw new UnsupportedAlgorithmException(alg);
        }
    }

    public static JwsAlgorithm GetJwsAlgorithmWrapper(Jwk jwk)
    {
        switch (jwk.Kty)
        {
            case "EC":
                switch (jwk.Crv)
                {
                    case Curve.CurveNameP256: // "P_256":
                        return JwsAlgorithm.ES256;
                    case Curve.CurveNameSecp256k1:
                        return JwsAlgorithm.ES256K;
                    default:
                        throw new UnsupportedCurveException(jwk.Crv);
                }
            case "OKP": //Octet Key Pair
                switch (jwk.Crv)
                {
                    case Curve.CurveNameEd25519:
                        //TODO newly supported
                        return JwsAlgorithm.EdDSA;
                    default:
                        throw new UnsupportedCurveException(jwk.Crv);
                }
            default:
                throw new UnsupportedJwkException(jwk.GetType().Name);
        }
    }

    //TODO moved it here
    public static Message Unpack(JwsParseResult jwsParseResult, RecipientKeySelector keySelector, UnpackResultBuilder metadataUnpackResultBuilder)
    {
        if (jwsParseResult.Token.Signatures == null)
        {
            throw new MalformedMessageException("Empty signatures");
        }

        foreach (var it in jwsParseResult.Token.Signatures)
        {
            var kidObject = it.UnprotectedHeader["kid"] ?? throw new MalformedMessageException("JWS Unprotected Per-Signature header must be present");
            var kidJsonElement = (JsonElement)kidObject;
            var kid = kidJsonElement.ToString();
            var key = keySelector.FindVerificationKey(kid);
            if (key == null)
            {
                throw new MalformedMessageException("No key found for kid: " + kidObject);
            }

            var alg = GetCryptoAlg(it);
            Verify(it, alg, key);

            // TODO: support multiple signatures on Metadata level
            metadataUnpackResultBuilder.SignAlg(alg).SignFrom(kid);
        }

        var unpackedMessage = jwsParseResult.Token.Payload.JsonDictionary;

        metadataUnpackResultBuilder
            .NonRepudiation(true)
            .Authenticated(true)
            .SignedMessage(jwsParseResult.RawMessage);

        var parseResult = JwmParseResult.Parse(unpackedMessage);
        return parseResult switch
        {
            JwmParseResult jwm => JwmExtensions.Unpack(jwm, keySelector, metadataUnpackResultBuilder),
            _ => throw new MalformedMessageException("Malformed Message")
        };
    }
}