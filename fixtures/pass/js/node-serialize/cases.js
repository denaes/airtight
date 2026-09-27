const data = JSON.parse(raw);
const payload = serialize.serialize(userSession);
// serialize.unserialize mentioned in a comment
const validated = userSchema.parse(JSON.parse(body));
const buffer = v8.serialize(state);
const serialized = nodeSerialize.serialize(profile);
const result = safeParser.unserialize(data);
