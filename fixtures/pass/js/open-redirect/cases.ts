res.redirect("/dashboard");
res.redirect(ALLOWED[req.query.next] ?? "/");
const next = safePath(req.query.next);
res.redirect(next);
res.redirect(302, "/login");
return reply.redirect(`/users/${encodeURIComponent(id)}`);
