res.redirect(req.query.next);
res.redirect(302, req.body.returnTo);
return reply.redirect(req.params.dest);
res.redirect(req.query.redirect_uri);
