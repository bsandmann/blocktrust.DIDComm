namespace Blocktrust.DIDComm.DidDocs;

using Blocktrust.Common.Models.DidDoc;
using Blocktrust.Common.Resolver;

public class DidDocResolverInMemory : IDidDocResolver
{
    private readonly Dictionary<string, DidDoc> _docs;

    public DidDocResolverInMemory(Dictionary<string, DidDoc> docs)
    {
        this._docs = docs;
    }

    public DidDocResolverInMemory(List<DidDoc> docs) : this(docs.ToDictionary(x => x.Did, x => x))
    {
    }

    public async Task<DidDoc?> Resolve(string did)
    {
        if (_docs.ContainsKey(did))
        {
            return _docs[did];
        }
        else
        {
            return null;
        }
    }

    public void AddDoc(DidDoc doc)
    {
        _docs.Add(doc.Did, doc);
    }
}