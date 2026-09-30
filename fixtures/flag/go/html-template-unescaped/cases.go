package main

import (
	"html/template"
	"net/http"
)

type Context struct{}

func (c *Context) Query(key string) string { return "" }
func (c *Context) Param(key string) string { return "" }

type Params struct{}

func (p Params) Get(key string) string { return "" }

func vulnTemplateEscaping(r *http.Request, req *http.Request, c *Context, params Params, userInput, untrustedHTML, customInput string) {
	// Shape 1: template.HTML with URL query parameter
	_ = template.HTML(r.URL.Query().Get("msg"))

	// Shape 2: template.JS with form value
	_ = template.JS(r.FormValue("callback"))

	// Shape 3: template.HTML with framework context query
	_ = template.HTML(c.Query("content"))

	// Shape 4: template.URL with request URL query
	_ = template.URL(req.URL.Query().Get("next"))

	// Shape 5: template.CSS with user input variable
	_ = template.CSS(userInput)

	// Shape 6: template.HTMLAttr with route param
	_ = template.HTMLAttr(c.Param("attr"))

	// Shape 7: template.HTML with untrusted HTML string
	_ = template.HTML(untrustedHTML)

	// Shape 8: template.JS with params query
	_ = template.JS(params.Get("fn"))

	// Shape 9: template.HTML with variable named customInput
	_ = template.HTML(customInput)
}
