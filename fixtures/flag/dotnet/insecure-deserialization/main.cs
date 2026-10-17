using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;

public class DeserTest {
    public void Run(Stream stream, Stream memStream, Stream networkStream) {
        var formatter = new BinaryFormatter(); var obj = formatter.Deserialize(stream);
        var res = new NetDataContractSerializer().Deserialize(memStream);
        var serializer = new SoapFormatter(); serializer.Deserialize(networkStream);
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };
    }
}
