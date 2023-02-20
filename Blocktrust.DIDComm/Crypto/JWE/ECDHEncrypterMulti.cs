namespace Blocktrust.DIDComm.Crypto.JWE;

using System.Text;
using Blocktrust.Common.Converter;
using JWM;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

public class ECDHEncrypterMulti : IJWEEncrypterMulti
{
    public ECDHEncrypterMulti(List<(UnprotectedHeader, Jwk)> recipient)
    {
        this.Recipients = recipient;
    }

    public List<(UnprotectedHeader, Jwk)> Recipients { get; }

    public JweCryptoParts Encrypt(JweHeader header, JwePayload Payload)
    {
        var keyGenerator = new ECKeyPairGenerator();

        X9ECParameters ecParams;
        var recipientCurve = Recipients.First().Item2.Crv;

        var allCurves = Recipients.Select(p => p.Item2.Crv).ToList().Any(p => p != recipientCurve);
        if (allCurves)
        {
            //TODO simple assumption based on the Kotlin tests
            throw new NotSupportedException("All Recipients must have the same curve");
        }

        if (recipientCurve== "P-256")
        {
            ecParams = SecNamedCurves.GetByName("secp256r1");
        }
        else if (recipientCurve== "P-384")
        {
            ecParams = SecNamedCurves.GetByName("secp384r1");
        }
        else if (recipientCurve == "P-521")
        {
            ecParams = SecNamedCurves.GetByName("secp521r1");
        }
        else
        {
            throw new NotSupportedException();
        }

        ECCurve curve = ecParams.Curve;

        var domainParameters = new ECDomainParameters(curve, ecParams.G, ecParams.N, ecParams.H);
        keyGenerator.Init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));
        var keys = keyGenerator.GenerateKeyPair();


        var publicKey = (ECPublicKeyParameters)keys.Public;
        var privateKey = (ECPrivateKeyParameters)keys.Private;

        // Update the header
        //Shitty way of building the header
        var njwk = new Jwk();
        njwk.Kty = "EC";

        //TODO unclear where to get this from exaclty
        //this is a aincorrect assumption and I need the right curves here!

        njwk.Crv = recipientCurve;
        njwk.X = Base64Url.Encode(publicKey.Q.XCoord.GetEncoded());
        njwk.Y = Base64Url.Encode(publicKey.Q.YCoord.GetEncoded());
        header.Epk(njwk);

        var sharedKeys = new List<(UnprotectedHeader, Byte[])>();
        foreach (var recipient in Recipients)
        {
            //Derevied Shared Secret

            var Z = CommonCrypto.DeriveSharedSecret(recipient.Item2, privateKey.D.ToByteArray());

            // var z = ECDH1PU.DeriveSenderZ(privateKeyOfSender, publicKeyOfRecipient, privateKey.D.ToByteArray());
            sharedKeys.Add((recipient.Item1, Z));
        }

        var payload = Encoding.UTF8.GetBytes(Payload.JsonString);
        var r = ECDH.EncryptMulti(header, sharedKeys, payload);

        return r;
    }
}