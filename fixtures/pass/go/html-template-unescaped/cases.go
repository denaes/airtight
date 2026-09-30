package main

import (
	"html/template"
	"io"
	"net/http"
)

func safeTemplateEscaping(w io.Writer, tmpl *template.Template, r *http.Request, rawInput string) {
	// Near-miss 1: Static HTML literal
	_ = template.HTML("<b>Safe static notification</b>")

	// Near-miss 2: Explicit HTML escape utility function
	_ = template.HTMLEscapeString(rawInput)

	// Near-miss 3: Commented out unsafe conversion
	// _ = template.HTML(r.URL.Query().Get("msg"))

	// Near-miss 4: Safe standard template rendering with auto-escaping intact
	_ = tmpl.Execute(w, r.URL.Query().Get("msg"))

	// Near-miss 5: Static JS script literal
	_ = template.JS("console.log('static analytics initialized');")

	// Near-miss 6: Static URL literal
	_ = template.URL("https://example.com/safe-destination")

	// Near-miss 7: Static CSS literal
	_ = template.CSS("body { margin: 0; padding: 0; }")

	// Near-miss 8: Static HTML attribute literal
	_ = template.HTMLAttr("readonly")

	// Near-miss 9: Conversion of sanitized markup string
	sanitizedMarkup := "<b>clean</b>"
	_ = template.HTML(sanitizedMarkup)
}
