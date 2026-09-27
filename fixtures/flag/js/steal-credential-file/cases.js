const sshKey = fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'), 'utf8');
const awsCreds = fs.readFileSync('/root/.aws/credentials');
fs.readFile(path.join(home, '.ssh', 'id_ed25519'), cb);
const kubeConfig = fs.readFileSync(path.join(os.homedir(), '.kube/config'));
const npmToken = fs.readFileSync('/home/user/.npmrc');
