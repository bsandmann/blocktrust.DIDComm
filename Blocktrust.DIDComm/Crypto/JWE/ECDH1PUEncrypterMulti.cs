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

public class ECDH1PUEncrypterMulti : IJWEEncrypterMulti
{
    public ECDH1PUEncrypterMulti(Jwk sender, List<(UnprotectedHeader, Jwk)> recipient)
    {
        this.Sender = sender;
        this.Recipients = recipient;
    }

    public Jwk Sender { get; }
    public List<(UnprotectedHeader, Jwk)> Recipients { get; }

    public JweCryptoParts Encrypt(JweHeader header, JwePayload Payload)
    {
        X9ECParameters ecParams;

        if (Sender.Crv == "P-256")
        {
            ecParams = SecNamedCurves.GetByName("secp256r1");
        }
        else if (Sender.Crv == "P-384")
        {
            ecParams = SecNamedCurves.GetByName("secp384r1");
        }
        else if (Sender.Crv == "P-521")
        {
            ecParams = SecNamedCurves.GetByName("secp521r1");
        }
        else
        {
            throw new NotSupportedException();
        }

        ECCurve curve = ecParams.Curve;


        var payload = Encoding.UTF8.GetBytes(Payload.JsonString);

        // generate public and private key
        var keyGenerator = new ECKeyPairGenerator();

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

        njwk.Crv = Sender.Crv;// "P-256";
        njwk.X = Base64Url.Encode(publicKey.Q.XCoord.GetEncoded());
        njwk.Y = Base64Url.Encode(publicKey.Q.YCoord.GetEncoded());
        header.Epk(njwk);
        //why doensit it come from the recipeints of the jwe-object?

        var sharedKeys = new List<(UnprotectedHeader, Byte[])>();
        foreach (var recipient in Recipients)
        {
            //Derevied Shared Secret
            var privateKeyOfSender = Base64Url.Decode(Sender.D);
            var Ze = CommonCrypto.DeriveSharedSecret(recipient.Item2, privateKey.D.ToByteArray());
            var Zs = CommonCrypto.DeriveSharedSecret(recipient.Item2, privateKeyOfSender);
            var Z = Ze.Concat(Zs).ToArray();

            // var z = ECDH1PU.DeriveSenderZ(privateKeyOfSender, publicKeyOfRecipient, privateKey.D.ToByteArray());
            sharedKeys.Add((recipient.Item1, Z));
        }

        var r = ECDH1PU.EncryptMulti(header, sharedKeys, payload);

        return r;
    }
}