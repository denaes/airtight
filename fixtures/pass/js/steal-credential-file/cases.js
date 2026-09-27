const cfg = fs.readFileSync(path.join(__dirname, 'config.json'));
fs.readFile('./package.json', 'utf8', cb);
const cert = fs.readFileSync(process.env.TLS_CERT_PATH);
const doc = fs.readFileSync('README.md');
const stream = fs.createReadStream('data.csv');
