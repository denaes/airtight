# Demo

`vulnerable-shop/` is a small storefront service written the way a model
writes code when nobody has asked it about security: it works, and it is full
of the shortcuts that make it work.

It is deliberately vulnerable. It is excluded from airtight's own self-scan
and it is not an example of anything to copy.

Two of its files — `src/config.js` and `Dockerfile` — are generated from
[`../templates/`](../templates/) by `npm run gen:secrets`, because their
committed form would carry live-shaped provider tokens and trip
secret-scanning push protection. The templates show exactly what lands.

## Run it

```bash
npm run build:rules
node scripts/demo.mjs
```

## What airtight finds

<!-- numbers are kept current by scripts/demo.mjs --check in CI -->

```
total findings:   54
distinct rules:   50
by priority:      23 P0, 16 P1, 11 P2, 4 P3
by pack:          ci=5 container=7 dep=7 js=9 k8s=10 py=5 secret=4 terraform=7

immediate tier:   32 distinct rules would interrupt an edit
```

Ten files, 51 distinct rules, every pack. The full list is in
[`expected-findings.txt`](expected-findings.txt), which CI diffs on every
commit — so these numbers cannot quietly stop being true.

## The interesting part

Read `src/api/orders.js`. Nothing in it looks careless:

```js
const rows = await db.query(`SELECT * FROM orders WHERE customer_id = ${req.query.customer}`);
```

That is a template literal, which is the modern way to build a string, used
with a query method, which is the right method. It reads like current code.
It is also SQL injection, and the customer id comes straight off the query
string.

```js
const file = path.join('/var/invoices', req.params.name);
res.sendFile(file);
```

`path.join` looks like the careful choice. It resolves `../` happily.

```js
const upstream = await fetch(req.query.url);
```

One line, obviously useful, and it points your server at
`169.254.169.254` on request.

This is the whole argument for the project. These are not the mistakes of
someone who does not know better; they are the shapes that appear when the
goal is *make it work*, which is the goal a model optimises for unless told
otherwise.

## The part the engine cannot do

The demo also contains things no rule will ever catch, left in on purpose:

- `listOrders` filters by a customer id taken from the request. There is no
  check that the caller *is* that customer. That is an IDOR, it is the most
  common serious bug in real applications, and it is invisible to pattern
  matching because the code is doing exactly what it says.
- `require_admin` in `report.py` is an `assert`, which Python removes under
  `-O`. The engine catches the `assert`; only a reader notices that the whole
  authorization model rests on it.

Run `/airtight review demo/vulnerable-shop` to see the model layer work on
those. The engine gives you 55 findings in under a second; the review tells
you which one an attacker reaches first.

## What this demo does not prove

It says nothing about false positives. Every rule here was written against
fixtures by the same author, and the demo was written to trigger them. The
number that matters — how often airtight is wrong on a repository nobody
wrote for it — is not measured yet, and the README says so.
