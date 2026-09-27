Runtime.getRuntime().exec("sh -c " + userInput);
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
new ProcessBuilder("bash", "-c", request.getParameter("cmd"));
new ProcessBuilder("/bin/sh", "-c", query + " " + arg);
new ProcessBuilder("cmd.exe", "/c", userInput).start();
new ProcessBuilder("bash", "-c", "echo " + userInput);
