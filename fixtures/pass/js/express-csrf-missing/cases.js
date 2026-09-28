csurf();
const csrfProtection = csurf({ ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] });
app.use(csrf());
// csurf({ ignoreMethods: ['POST'] });
const options = { ignoreMethods: ['GET'] };
csrfProtection(options);
