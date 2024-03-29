﻿namespace Blocktrust.DIDComm.Crypto.Keys;

using System.Runtime.InteropServices;
using Blocktrust.Common.Exceptions;
using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Models.Secrets;
using Blocktrust.Common.Resolver;
using Exceptions;
using FluentResults;
using Utils;

public class SenderKeySelector
{
    private readonly IDidDocResolver _didDocResolver;
    private readonly ISecretResolver _secretResolver;

    public SenderKeySelector(IDidDocResolver didDocResolver, ISecretResolver secretResolver)
    {
        this._didDocResolver = didDocResolver;
        this._secretResolver = secretResolver;
    }

    public async Task<Result<Key>> FindSigningKey(string signFrom)
    {
        if (DidUtils.IsDidFragment(signFrom))
        {
            var secret = await _secretResolver.FindKey(signFrom);
            if (secret is null)
            {
                return Result.Fail($"Unable to find secret for signing of '{signFrom}'");
            }

            return Result.Ok(Key.FromSecret(secret!));
        }
        else
        {
            var didDoc = await _didDocResolver.Resolve(signFrom);
            if (didDoc is null)
            {
                return Result.Fail($"DID '{signFrom}' could not be resolved");
            }

            var authentication = didDoc.Authentications.FirstOrDefault();
            if (authentication is null)
            {
                return Result.Fail($"The DID Doc '{didDoc.Did}' does not contain compatible 'authentication' verification methods");
            }

            var secret = await _secretResolver.FindKey(didDoc.Authentications.First());
            if (secret is null)
            {
                return Result.Fail($"Unable to find secret for signing of '{signFrom}'");
            }

            return Result.Ok(Key.FromSecret(secret!));
        }
    }

    public async Task<Result<(Key, List<Key>)>> FindAuthCryptKeys(string from, string to)
    {
        var didFrom = DidUtils.DivideDidFragment(from);
        var didTo = DidUtils.DivideDidFragment(to);
        var didDocTo = await _didDocResolver.Resolve(didTo.First());
        if (didDocTo is null)
        {
            return Result.Fail($"DID '{didTo.First()}' could not be resolved");
        }

        if (DidUtils.IsDidFragment(from))
        {
            var secret = await _secretResolver.FindKey(from);
            if (secret is null)
            {
                return Result.Fail($"Unable to find secret of '{from}'");
            }

            var sender = Key.FromSecret(secret);
            var recipients = FindRecipientKeys(didDocTo, to, sender.Curve);
            if (recipients.Count == 0)
            {
                return Result.Fail($"The recipient '{to}' curve is not compatible to '{sender.Curve.Name}'");
            }

            return Result.Ok((
                sender: sender,
                recipients: recipients
            ));
        }
        else
        {
            var didDocFrom = await _didDocResolver.Resolve(didFrom.First());
            if (didDocFrom is null)
            {
                return Result.Fail($"DID '{didFrom.First()}' could not be resolved");
            }

            var keyAgreements = didDocFrom.KeyAgreements.ToList();
            var keyPairList = new List<(Key, List<Key>)>();
            foreach (var keyAgreement in keyAgreements)
            {
                var key = await _secretResolver.FindKey(keyAgreement);
                if (key != null)
                {
                    var keyPair = (Key.FromSecret(key), FindRecipientKeys(didDocTo, to, Key.FromSecret(key).Curve));
                    keyPairList.Add(keyPair);
                }
            }

            var compatibleKeys = keyPairList.FirstOrDefault(pair => pair.Item2.Any());


            if (compatibleKeys.Item1 is null)
            {
                return Result.Fail($"The DID Docs '{didDocFrom.Did}' and '{didDocTo.Did}' do not contain compatible 'keyAgreement' verification methods");
            }

            return compatibleKeys;
        }
    }

    public async Task<Result<List<Key>>> FindAnonCryptKeys(string to)
    {
        var did = DidUtils.DivideDidFragment(to);
        var didDoc = await _didDocResolver.Resolve(did.First());
        if (didDoc is null)
        {
            return Result.Fail($"DID '{did.First()}' could not be resolved");
        }

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
                : Result.Fail($"The DID Doc '{didDoc.Did}' does not contain compatible 'keyAgreement' verification methods");
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