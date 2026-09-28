collection.find({"name": "alice"})
db.users.find({"status": {"$eq": "active"}})
# db.users.find({"$where": user_js})
config = {"$where": "some value"}
collection.find_one({"_id": doc_id})
db.items.count_documents({"category": "books", "price": {"$lt": 20}})
collection.delete_many({"active": False})
db.users.update_many({"status": "inactive"}, {"$set": {"archived": True}})
