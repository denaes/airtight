// True positive cases for java/steal-credential-file
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Cases {
    public void flagCases() throws Exception {
        // Case 1: FileInputStream on private id_rsa
        FileInputStream fis = new FileInputStream("/home/user/.ssh/id_rsa");

        // Case 2: Files.readString on aws credentials
        String aws = Files.readString(Paths.get("/root/.aws/credentials"));

        // Case 3: FileReader on kubeconfig
        FileReader fr = new FileReader("/home/deploy/.kube/config");

        // Case 4: Files.readAllBytes on docker config
        byte[] docker = Files.readAllBytes(Path.of("/var/run/.docker/config.json"));

        // Case 5: Files.readAllLines on ed25519 key
        var edKey = Files.readAllLines(Path.of("/root/.ssh/id_ed25519"));
    }
}
