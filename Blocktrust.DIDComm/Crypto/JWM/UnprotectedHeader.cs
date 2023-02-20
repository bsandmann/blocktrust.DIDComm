namespace Blocktrust.DIDComm.Crypto.JWM;

public class UnprotectedHeader
{
   public Dictionary<string, object> _unprotectedHeader { get; set; }



   public UnprotectedHeader(Dictionary<string, object> unprotectedHeader)
   {
      _unprotectedHeader = unprotectedHeader;
   }

   public UnprotectedHeader()
   {
      _unprotectedHeader = new Dictionary<string, object>();
   }
   
   public UnprotectedHeader Builder()
   {
      return this;
   }
   
   public UnprotectedHeader KeyId(string keyId)
   {
      _unprotectedHeader.Add("kid", keyId);
      return this;
   }
   
   public UnprotectedHeader Build()
   {
      return this;
   }
}