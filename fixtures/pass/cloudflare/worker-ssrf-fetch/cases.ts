const resp1 = await fetch("https://api.example.com/v1/data");
if (ALLOWED_HOSTS.includes(targetUrl.hostname)) { await fetch(targetUrl); }
const resp2 = await fetch(`${env.BACKEND_API}/users`);
const resp3 = await fetch(new Request("https://api.stripe.com/v1/charges"));
const resp4 = await fetch(ALLOWLIST_URL, { headers });
const resp5 = await fetch(validateUrl(inputUrl));
