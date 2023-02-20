namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Exceptions;
using Blocktrust.Common.Resolver;
using Exceptions;
using Utils;

public class RecipientKeySelector
{
    private readonly IDidDocResolver _ididDocResolver;
    private readonly ISecretResolver _secretResolver;

    public RecipientKeySelector(IDidDocResolver ididDocResolver, ISecretResolver secretResolver)
    {
        this._ididDocResolver = ididDocResolver;
        this._secretResolver = secretResolver;
    }

    public Key FindVerificationKey(string signFrom)
    {
        if (!DidUtils.IsDidFragment(signFrom))
        {
            throw new Exception($"'DID URL' is expected as a signature verification key. Got: {signFrom}");
        }

        var did = DidUtils.DivideDidFragment(signFrom);

        var didDoc = _ididDocResolver.Resolve(did.First());
        if (didDoc == null)
        {
            throw new DidUrlNotFoundException(signFrom, did.First());
        }

        return Key.FromVerificationMethod(didDoc.FindVerificationMethod(signFrom));
    }

    public (Key, List<Key>) FindAuthCryptKeys(string from, List<string> to)
    {
        if (!DidUtils.IsDidFragment(from))
        {
            throw new Exception($"'DID URL' is expected as a sender key. Got: {from}");
        }

        var did = DidUtils.DivideDidFragment(from);

        //TODO modified
        var didDoc = _ididDocResolver.Resolve(did.First());
        if (didDoc == null)
        {
            //TODO modified
            throw new DidUrlNotFoundException(from, did.First());
        }

        var verificationMethod = didDoc.FindVerificationMethod(from);
        var senderKey = Key.FromVerificationMethod(verificationMethod);
        var recipientKeys = FindRecipientKeys(to, senderKey.Curve);

        return (senderKey, recipientKeys);
    }

    public bool HasKeysForForwardNext(string next)
    {
        var nextKids = DidUtils.IsDidFragment(next) ? new List<string> { next } : _ididDocResolver.Resolve(next)?.KeyAgreements ?? new List<string>();

        return _secretResolver.FindKeys(nextKids).Any();
    }

    public IEnumerable<Key> FindAnonCryptKeys(List<string> to)
    {
        foreach (var recipient in to)
        {
            if (!DidUtils.IsDidFragment(recipient))
            {
                throw new Exception($"'DID URL' is expected as a recipient key. Got: {recipient}");
            }
        }

        return FindRecipientKeys(to, null);
    }

    private List<Key> FindRecipientKeys(List<string> to, Curve curve)
    {
        var keys = _secretResolver.FindKeys(to);
        if (!keys.Any())
        {
            throw new SecretNotFoundException(string.Join(",", to));
        }

        return keys
            .Where(k => DidUtils.IsDidFragment(k))
            .Select(k => _secretResolver.FindKey(k))
            .Where(k => k != null)
            .Select(k => Key.FromSecret(k))
            .Select(k =>
            {
                if (curve != null && curve != k.Curve)
                {
                    throw new IncompatibleCryptoException($"The recipient '{k.Id}' curve is not compatible to '{curve.Name}'");
                }

                return k;
            }).ToList();
    }
}