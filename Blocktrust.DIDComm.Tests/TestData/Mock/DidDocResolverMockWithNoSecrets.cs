namespace Blocktrust.DIDComm.Tests.TestData.Mock;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;
using DIDDoc;
using DidDocs;

public class DidDocResolverMockWithNoSecrets : IDidDocResolver
{
    private DidDocResolverInMemory _didDocResolver;

    public DidDocResolverMockWithNoSecrets()
    {
        _didDocResolver = new DidDocResolverInMemory(
            new List<DidDoc>
            {
                DIDDocAlice.DID_DOC_ALICE_WITH_NO_SECRETS,
                DIDDocBob.DID_DOC_BOB_WITH_NO_SECRETS,
                DIDDocCharlie.DID_DOC_CHARLIE,
                DIDDocMediator1.DID_DOC_MEDIATOR1,
                DIDDocMediator2.DID_DOC_MEDIATOR2,
                DIDDocEllie.DID_DOC_ELLIE
            });
    }

    public async Task<DidDoc?> Resolve(string did)
    {
        return await _didDocResolver.Resolve(did);
    }
}