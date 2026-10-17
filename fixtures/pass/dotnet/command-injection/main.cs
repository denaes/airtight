using System.Diagnostics;

public class CmdPassTest {
    public void SafeRun() {
        Process.Start("git", "status");
        Process.Start("notepad.exe");
        var psi = new ProcessStartInfo("ping", "-n 1 127.0.0.1");
        Process.Start(new ProcessStartInfo { FileName = "ls", ArgumentList = { "-l" } });
        // Process.Start("cmd.exe", "/c " + commented);
    }
}
