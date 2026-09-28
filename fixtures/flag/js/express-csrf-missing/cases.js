csurf({ ignoreMethods: ['POST'] });
const csrfProtection = csurf({ ignoreMethods: ['GET', 'POST'] });
app.use(csrf({ ignoreMethods: ['PUT', 'DELETE'] }));
const protection = csrfProtection({ cookie: true, ignoreMethods: ['PATCH'] });
app.use(csurf({ cookie: true, ignoreMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'] }));
