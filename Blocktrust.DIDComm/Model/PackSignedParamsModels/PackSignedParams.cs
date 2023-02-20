namespace Blocktrust.DIDComm.Model.PackSignedParamsModels;

using Blocktrust.Common.Resolver;
using Message.Messages;

public class PackSignedParams
    {
        public Message Message;
        public string SignFrom;
        public string FromPriorIssuerKid;
        public IDidDocResolver IdidDocResolver;
        public ISecretResolver SecretResolver;

        public PackSignedParams(PackSignedParamsBuilder packSignedParamsBuilder)
        {
            Message = packSignedParamsBuilder.Message;
            SignFrom = packSignedParamsBuilder.SignFrom;
            FromPriorIssuerKid = packSignedParamsBuilder.fromPriorIssuerKid;
            IdidDocResolver = packSignedParamsBuilder.IdidDocResolver;
            SecretResolver = packSignedParamsBuilder.secretResolver;
        }

       
    }
