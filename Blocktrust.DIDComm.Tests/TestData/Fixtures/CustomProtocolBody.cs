namespace Blocktrust.DIDComm.Tests.TestData.Fixtures;

public class CustomProtocolBody
{
    public string id { get; set; }
    public string name { get; set; }
    public bool custom { get; set; }
    public object year { get; set; }

    public CustomProtocolBody(string id, string name, bool custom, object year)
    {
        this.id = id;
        this.name = name;
        this.custom = custom;
        this.year = year;
    }
}