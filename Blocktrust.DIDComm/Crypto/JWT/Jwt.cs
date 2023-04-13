namespace Blocktrust.DIDComm.Crypto.JWT;

using System.Text;
using System.Text.Json;
using Blocktrust.Common.Converter;
using Exceptions;
using JWS;
using Keys;
using Utils;

public static class Jwt
{
    public static string SignJwt(Dictionary<string, object> jwtClaimsSet, Key key)
    {
        var jwk = key.Jwk;
        var alg = Jws.GetJwsAlgorithmWrapper(jwk);
        string token = String.Empty;
        var headerUnbuild = new JwsHeader().Builder(alg, key);
        var header = headerUnbuild.Build();
        try
        {
            //TODO this should be build analogous to the Encryption, with first establishing the
            //encryptor and then the signing with an interface for that class and not everything in here
            //ANd then the building of the token should be done afterwards for all and not in each method seperattly
            switch (alg)
            {
                case JwsAlgorithm.ES256:
                    // ENsure surrport for signing 
                    var headerAsBase64 = headerUnbuild.ToBase64();
                    var claimsSerialized = JsonSerializer.Serialize(jwtClaimsSet, SerializationOptions.UnsafeRelaxedEscaping);
                    var claimsAsBytes = Encoding.UTF8.GetBytes(claimsSerialized);
                    var claimsAsBas64 = Base64Url.Encode(claimsAsBytes);

                    var inputString = string.Concat(headerAsBase64, ".", claimsAsBas64);
                    var message = Encoding.UTF8.GetBytes(inputString);
                    var signature = ECDSA.Sign(message, key.Jwk);
                    token = string.Concat(inputString, ".", Base64Url.Encode(signature));

                    break;
                case JwsAlgorithm.EdDSA:

                    //TODO the same code is in the JWSExtension without Jose
                    var headerAsBase64x = headerUnbuild.ToBase64();
                    var claimsSerializedx = JsonSerializer.Serialize(jwtClaimsSet, SerializationOptions.UnsafeRelaxedEscaping);
                    var claimsAsBytesx = Encoding.UTF8.GetBytes(claimsSerializedx);
                    var claimsAsBas64x = Base64Url.Encode(claimsAsBytesx);

                    var inputStringx = string.Concat(headerAsBase64x, ".", claimsAsBas64x);

                    var privateKeyBytes = Base64Url.Decode(key.Jwk.D);
                    var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
                        { D = privateKeyBytes });

                    var messagex = Encoding.UTF8.GetBytes(inputStringx);
                    var signaturxe = edDsa.Sign(messagex);

                    token = string.Concat(inputStringx, ".", Base64Url.Encode(signaturxe));
                    break;
                // case JwsAlgorithmWrapper.ES256K:
                //     signer = new ECDSASigner(jwk.AsKey<ECKey>());
                //     break;
                default:
                    throw new NotImplementedException();
            }
        }
        catch (Exception e)
        {
            throw new Exception("Unsupported algorithm");
        }

        return token;
    }

    public static Dictionary<string, object> VerifyJwt(string serializedJwt, Key key)
    {
        var jwk = key.Jwk;
        var alg = Jws.GetJwsAlgorithmWrapper(jwk);
        Dictionary<string, object> token = null;
        try
        {
            //TODO is all this duplicate code with JwsExtensions

            switch (alg)
            {
                case JwsAlgorithm.ES256:
                    //TODO this has to be written in a way it works for all kind of tokens
                    var split = serializedJwt.Split(".");
                    var header = split[0];
                    var body = split[1];
                    var signature = Base64Url.Decode(split[2]);
                    var inputString = string.Concat(header, ".", body);
                    var message = Encoding.UTF8.GetBytes(inputString);
                    var result = ECDSA.Verify(message, jwk, signature);

                    if (!result)
                    {
                        throw new Exception("Invalid signature!!");
                    }

                    var bodyString = Base64Url.Decode(body);
                    var tokenWithJsonObject = JsonSerializer.Deserialize<Dictionary<string, object>>(bodyString);
                    //TODO horrible ugly code. DRY
                    var dict = new Dictionary<string, object>();
                    foreach (var kvpair in tokenWithJsonObject)
                    {
                        var jsonElement = (JsonElement)kvpair.Value;
                        if (jsonElement.ValueKind == JsonValueKind.String)
                        {
                            dict.Add(kvpair.Key, jsonElement.GetString());
                        }
                        else if (jsonElement.ValueKind == JsonValueKind.Number)
                        {
                            dict.Add(kvpair.Key, jsonElement.GetInt64().ToString());
                        }
                        else
                        {
                            throw new Exception("Chance to improve the code");
                        }
                    }

                    return dict;

                    break;
                case JwsAlgorithm.EdDSA:
                    var publicKeyBytes = Base64Url.Decode(key.Jwk.X);
                    var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519)
                        { X = publicKeyBytes });
                    var keyId = jwk.KeyId;
                    
                    //TODO this has to be written in a way it works for all kind of tokens
                    var splitx = serializedJwt.Split(".");
                    var headerx = splitx[0];
                    var bodyx = splitx[1];
                    var signaturex = Base64Url.Decode(splitx[2]);
                    var inputStringx = string.Concat(headerx, ".", bodyx);
                    var messagex = Encoding.UTF8.GetBytes(inputStringx);
                    var resultx = edDsa.Verify(messagex,signaturex);

                    if (!resultx)
                    {
                        throw new Exception("Invalid signature!!");
                    }
                    

                    var bodyStringx = Base64Url.Decode(bodyx);
                    var tokenWithJsonObjectx = JsonSerializer.Deserialize<Dictionary<string, object>>(bodyStringx);
                    //TODO horrible ugly code. DRY
                    var dictx = new Dictionary<string, object>();
                    foreach (var kvpair in tokenWithJsonObjectx)
                    {
                        var jsonElement = (JsonElement)kvpair.Value;
                        if (jsonElement.ValueKind == JsonValueKind.String)
                        {
                            dictx.Add(kvpair.Key, jsonElement.GetString());
                        }
                        else if (jsonElement.ValueKind == JsonValueKind.Number)
                        {
                            dictx.Add(kvpair.Key, jsonElement.GetInt64().ToString());
                        }
                        else
                        {
                            throw new Exception("Chance to improve the code");
                        }
                    }
                    
                    return dictx;
                // case JwsAlgorithmWrapper.ES256K:
                //     signer = new ECDSASigner(jwk.AsKey<ECKey>());
                //     break;
              
                default:
                    throw new NotImplementedException();
            }
        }
        catch (MalformedMessageException e)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new MalformedMessageException("JWT has an invalid signature");
        }
      
    }
}