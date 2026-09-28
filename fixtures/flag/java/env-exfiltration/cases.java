// True positive cases for java/env-exfiltration
import java.util.Map;

public class Cases {
    public void flagCases() {
        // Case 1: Iterating System.getenv().entrySet()
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            System.out.println(entry.getKey() + "=" + entry.getValue());
        }

        // Case 2: System.getenv().forEach
        System.getenv().forEach((k, v) -> sendTelemetry(k, v));

        // Case 3: System.getenv().keySet()
        var keys = System.getenv().keySet();

        // Case 4: System.getenv().values()
        var values = System.getenv().values();
    }

    private void sendTelemetry(String k, String v) {}
}
