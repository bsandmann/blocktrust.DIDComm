﻿namespace Blocktrust.DIDComm.Crypto.JWM;

using Keys;
using Message.Messages;
using Model.UnpackResultModels;

public static class JwmExtensions
{
    public static Message Unpack(
        JwmParseResult result,
        RecipientKeySelector keySelector,
        UnpackResultBuilder metadataUnpackResultBuilder)
    {
        metadataUnpackResultBuilder.FromPriorJwt(result.Message.FromPriorJwt);
        (Message updatedMessage, string fromPriorIssuerKid) = Operations.FromPrior.UnpackFromPrior(result.Message, keySelector);
         metadataUnpackResultBuilder.FromPriorIssuerKid(fromPriorIssuerKid);
        return updatedMessage;
    } 
}