using System.Text.Json;
using Newtonsoft.Json;

public class DeserPassTest {
    public void SafeRun(string jsonString, string json) {
        var obj = JsonSerializer.Deserialize<UserDto>(jsonString);
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        var data = JsonConvert.DeserializeObject<Order>(json);
        // formatter.Deserialize(commented);
        var doc = JsonDocument.Parse(json);
    }
}
