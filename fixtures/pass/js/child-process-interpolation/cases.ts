execFile("git", ["checkout", branch]);
spawn("convert", [input, output]);
execSync("git status --porcelain");
exec("npm ci");
const cmd = `git checkout ${branch}`; // built for display only
execFileSync("ping", ["-c", "1", host]);
