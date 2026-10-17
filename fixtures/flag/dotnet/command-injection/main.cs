using System.Diagnostics;

public class CmdTest {
    public void Run() {
        Process.Start("cmd.exe", "/c " + userInput);
        Process.Start("bash", $"-c {userScript}");
        Process.Start("powershell.exe", "-Command " + scriptInput);
        var psi = new ProcessStartInfo("cmd.exe", $"/c ping {host}");
    }
}
