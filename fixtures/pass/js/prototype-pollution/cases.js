Object.assign({}, source);
const clean = Object.assign(Object.create(null), source);
map.set(key, value);
if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
Object.freeze(Object.prototype);
const clone = structuredClone(source);
const safe = JSON.parse(JSON.stringify(source));
target[key] = source[key];
if (Object.prototype.hasOwnProperty.call(source, key)) target[key] = source[key];
