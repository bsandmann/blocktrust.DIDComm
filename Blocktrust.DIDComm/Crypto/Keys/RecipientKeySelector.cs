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

    public async Task<Key> FindVerificationKey(string signFrom)
    {
        if (!DidUtils.IsDidFragment(signFrom))
        {
            throw new Exception($"'DID URL' is expected as a signature verification key. Got: {signFrom}");
        }

        var did = DidUtils.DivideDidFragment(signFrom);

        var didDoc = await _ididDocResolver.Resolve(did.First());
        if (didDoc == null)
        {
            throw new DidUrlNotFoundException(signFrom, did.First());
        }

        return Key.FromVerificationMethod(didDoc.FindVerificationMethod(signFrom));
    }

    public async Task<(Key, List<Key>)> FindAuthCryptKeys(string from, List<string> to)
    {
        if (!DidUtils.IsDidFragment(from))
        {
            throw new Exception($"'DID URL' is expected as a sender key. Got: {from}");
        }

        var did = DidUtils.DivideDidFragment(from);

        //TODO modified
        var didDoc = await _ididDocResolver.Resolve(did.First());
        if (didDoc == null)
        {
            //TODO modified
            throw new DidUrlNotFoundException(from, did.First());
        }

        var verificationMethod = didDoc.FindVerificationMethod(from);
        var senderKey = Key.FromVerificationMethod(verificationMethod);
        var recipientKeys = await FindRecipientKeys(to, senderKey.Curve);

        return (senderKey, recipientKeys);
    }

    public async Task<bool> HasKeysForForwardNext(string next)
    {
        var nextKids = DidUtils.IsDidFragment(next) ? new List<string> { next } : (await _ididDocResolver.Resolve(next))?.KeyAgreements ?? new List<string>();

        return (await _secretResolver.FindKeys(nextKids)).Any();
    }

    public async Task<IEnumerable<Key>> FindAnonCryptKeys(List<string> to)
    {
        foreach (var recipient in to)
        {
            if (!DidUtils.IsDidFragment(recipient))
            {
                throw new Exception($"'DID URL' is expected as a recipient key. Got: {recipient}");
            }
        }

        return await FindRecipientKeys(to, null);
    }

    private async Task<List<Key>> FindRecipientKeys(List<string> to, Curve curve)
    {
        var keys = await _secretResolver.FindKeys(to);
        if (!keys.Any())
        {
            throw new SecretNotFoundException(string.Join(",", to));
        }

        var hs = new HashSet<Key>();
        foreach (var didFragment in keys.Where(p => DidUtils.IsDidFragment(p)))
        {
            var secret = await _secretResolver.FindKey(didFragment);
            if (secret != null)
            {
                var key = Key.FromSecret(secret);
                if (curve != null && curve != key.Curve)
                {
                    throw new IncompatibleCryptoException($"The recipient '{key.Id}' curve is not compatible to '{curve.Name}'");
                }
        
                hs.Add(key);
            }
        }

        return hs.ToList();
    }
}