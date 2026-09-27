package shop;

public class Service {
    public void runCommand(String userInput) throws Exception {
        Runtime.getRuntime().exec("sh -c " + userInput);
    }
}
