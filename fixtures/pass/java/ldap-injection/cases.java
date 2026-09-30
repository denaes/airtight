// ctx.search("ou=users", "(&(uid=" + username + ")(userPassword=" + pass + "))", controls);
ctx.search("ou=users", "(objectClass=person)", controls);
ctx.search(base, "(uid={0})", new Object[]{username}, controls);
ctx.search("ou=users", "(&(uid=" + LdapEncoder.filterEncode(username) + "))", controls);
ctx.search("ou=users", "(&(uid=" + filterEncode(username) + "))", controls);
searchService.search("ou=users", "(&(uid=" + username + "))", controls);
dirContext.search(base, "(cn={0})", new Object[]{userInput}, searchControls);
initialDirContext.search("ou=people", "(objectClass=user)", sc);
