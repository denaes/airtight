new ObjectInputStream(inputStream).readObject();
ObjectInputStream ois = new ObjectInputStream(in); Object obj = ois.readObject();
XMLDecoder decoder = new XMLDecoder(in); decoder.readObject();
User user = (User) ois.readUnshared();
Object data = new XMLDecoder(stream).readObject();
Order order = (Order) in.readObject();
