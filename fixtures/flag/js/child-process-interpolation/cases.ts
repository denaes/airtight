exec(`git checkout ${branch}`);
execSync("rm -rf " + dir);
child_process.exec(`convert ${input} ${output}`);
const out = execSync(`ping -c 1 ${host}`);
