new ProcessBuilder("git", "status");
new ProcessBuilder(Arrays.asList("ls", "-la"));
Runtime.getRuntime().exec(new String[]{"/usr/bin/env"});
Runtime.getRuntime().exec("whoami");
new ProcessBuilder("bash", "-c", "echo hello");
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "uptime"});
new ProcessBuilder("cmd.exe", "/c", "dir");
// Runtime.getRuntime().exec("sh -c " + userInput);
// Avoid invoking shell interpreters directly; pass arguments as an array to ProcessBuilder.
