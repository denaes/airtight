JSON.parse(data);
User user = objectMapper.readValue(json, User.class);
User user = gson.fromJson(json, User.class);
ValidatingObjectInputStream vois = new ValidatingObjectInputStream(in);
vois.accept(User.class, List.class);
Object obj = vois.readObject();
int bytesRead = in.read(buffer);
int b = inputStream.read();
int count = ois.readInt();
String text = ois.readUTF();
boolean flag = ois.readBoolean();
ois.defaultReadObject();
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.example.model.*;!*");
ois.setObjectInputFilter(filter);
// Object obj = new ObjectInputStream(inputStream).readObject();
/* ObjectInputStream ois = new ObjectInputStream(in); Object obj = ois.readObject(); */
 * ois.readUnshared();
