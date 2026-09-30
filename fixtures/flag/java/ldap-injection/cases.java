ctx.search("ou=users", "(&(uid=" + username + ")(userPassword=" + pass + "))", controls);
dirContext.search(base, "(cn=" + userInput + ")", searchControls);
ctx.search("dc=example,dc=com", String.format("(mail=%s)", email), ctls);
ctx.search(baseDn, String.format("(mail=%s)", email), ctls);
initialDirContext.search("ou=people", "(uid=" + req.getParameter("user") + ")", sc);
ctx.search(dn, "(&(objectClass=user)(sAMAccountName=" + user + "))", cons);
