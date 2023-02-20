namespace Blocktrust.DIDComm.Crypto.Keys;

using Blocktrust.Common.Exceptions;
using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Blocktrust.Common.Resolver;
using Exceptions;
using Utils;

public class SenderKeySelector
{
    private readonly IDidDocResolver _ididDocResolver;
    private readonly ISecretResolver _secretResolver;

    public SenderKeySelector(IDidDocResolver ididDocResolver, ISecretResolver secretResolver)
    {
        this._ididDocResolver = ididDocResolver;
        this._secretResolver = secretResolver;
    }

    public Key FindSigningKey(string signFrom)
    {
        if (DidUtils.IsDidFragment(signFrom))
        {
            var secret = _secretResolver.FindKey(signFrom) ?? throw new SecretNotFoundException(signFrom);
            return Key.FromSecret(secret);
        }
        else
        {
            var didDoc = _ididDocResolver.Resolve(signFrom) ?? throw new DidDocNotResolvedException(signFrom);
            var authentication = didDoc.Authentications.FirstOrDefault() ?? throw new DidDocException($"The DID Doc '{didDoc.Did}' does not contain compatible 'authentication' verification methods");
            var secret = _secretResolver.FindKey(didDoc.Authentications.FirstOrDefault());
            return Key.FromSecret(secret);
        }
    }

    public (Key, List<Key>) FindAuthCryptKeys(string from, string to)
    {
        var didFrom = DidUtils.DivideDidFragment(from);
        var didTo = DidUtils.DivideDidFragment(to);
        var didDocTo = _ididDocResolver.Resolve(didTo.First()) ?? throw new DidDocNotResolvedException(didTo.First());

        if (DidUtils.IsDidFragment(from))
        {
            Secret? secret = _secretResolver.FindKey(from);
            if (secret is null)
            {
                throw new SecretNotFoundException(from);
            }

            var sender = Key.FromSecret(secret);
            var recipients = FindRecipientKeys(didDocTo, to, sender.Curve);
            if (recipients.Count == 0)
            {
                throw new IncompatibleCryptoException($"The recipient '{to}' curve is not compatible to '{sender.Curve.Name}'");
            }

            return (
                sender: sender,
                recipients: recipients
            );
        }
        else
        {
            var didDocFrom = (_ididDocResolver.Resolve(didFrom.First()) ?? throw new DidDocNotResolvedException(didFrom.First()));
            
            var compatibleKeys =
                didDocFrom
                    .KeyAgreements
                    .ToList()
                    .Select(ka => _secretResolver.FindKey(ka))
                    .Where(opt => opt != null)
                    .Select(s => (Key.FromSecret(s), FindRecipientKeys(didDocTo, to, Key.FromSecret(s).Curve)))
                    .FirstOrDefault(pair => pair.Item2.Any());
            if (compatibleKeys.Item1 is null)
            {
                throw new IncompatibleCryptoException($"The DID Docs '{didDocFrom.Did}' and '{didDocTo.Did}' do not contain compatible 'keyAgreement' verification methods");
            }

            return compatibleKeys;
        }
    }

    public List<Key> FindAnonCryptKeys(string to)
    {
        var did = DidUtils.DivideDidFragment(to);
        var didDoc = _ididDocResolver.Resolve(did.First()) ?? throw new DidDocNotResolvedException(did.First());

        return DidUtils.IsDidFragment(to)
            ? new List<Key> { Key.FromVerificationMethod(didDoc.FindVerificationMethod(to)) }
            : didDoc.KeyAgreements
                .Select(didDoc.FindVerificationMethod)
                .Select(Key.FromVerificationMethod)
                .Select(key => key.Curve)
                .FirstOrDefault() is { } selectedCurve
                ? didDoc.KeyAgreements
                    .Select(didDoc.FindVerificationMethod)
                    .Select(Key.FromVerificationMethod)
                    .Where(key => selectedCurve == key.Curve)
                    .ToList()
                : throw new DidDocException($"The DID Doc '{didDoc.Did}' does not contain compatible 'keyAgreement' verification methods");
    }

    private List<Key> FindRecipientKeys(DidDoc didDoc, string to, Curve curve)
    {
        return DidUtils.IsDidFragment(to)
            ? didDoc.FindVerificationMethod(to) is { } method
                ? curve == (Key.FromVerificationMethod(method).Curve)
                    ? new List<Key> { Key.FromVerificationMethod(method) }
                    : new List<Key>()
                : new List<Key>()
            : didDoc.KeyAgreements
                .Select(didDoc.FindVerificationMethod)
                .Select(Key.FromVerificationMethod)
                .Where(key => curve == key.Curve)
                .ToList();
    }
}