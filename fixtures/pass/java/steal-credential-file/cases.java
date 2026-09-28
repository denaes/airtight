// False positive cases for java/steal-credential-file
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Cases {
    public void passCases() throws Exception {
        // Case 1: Reading regular application properties
        FileInputStream fis = new FileInputStream("src/main/resources/application.properties");

        // Case 2: Reading local schema file
        String schema = Files.readString(Paths.get("schema.sql"));

        // Case 3: Reading /etc/hosts
        FileReader fr = new FileReader("/etc/hosts");

        // Case 4: Reading data buffer
        byte[] data = Files.readAllBytes(Path.of("/tmp/data.bin"));

        // Case 5: Regular log reader
        var lines = Files.readAllLines(Path.of("/var/log/application.log"));

        // Case 6: Comment referencing credentials
        // FileInputStream key = new FileInputStream("/root/.ssh/id_rsa");
        String pub = Files.readString(Path.of("public.key"));
    }
}
