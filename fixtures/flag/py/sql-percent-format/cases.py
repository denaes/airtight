cur.execute("SELECT * FROM users WHERE id = %s" % uid)
cur.execute("DELETE FROM t WHERE k = %s" % key)
conn.execute("UPDATE t SET a = %s" % val)
cursor.execute("INSERT INTO t VALUES (%s)" % v)
