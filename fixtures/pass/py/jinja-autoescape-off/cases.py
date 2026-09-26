env = Environment(autoescape=True)
tmpl = Environment(loader=loader, autoescape=select_autoescape(["html"]))
app.jinja_env.autoescape = True
e2 = Environment(autoescape=select_autoescape(), loader=fs)
AUTOESCAPE_ENABLED = True
# autoescape stays on; use Markup for trusted fragments
