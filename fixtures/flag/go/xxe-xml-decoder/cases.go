// True positive cases for go/xxe-xml-decoder
package main

import (
	"encoding/xml"
	"io"
	"strings"
)

func customCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	return input, nil
}

func flagCases(r io.Reader) {
	entityMap := map[string]string{"custom": "value"}

	// Case 1: d.Entity set to xml.HTMLEntity
	d := xml.NewDecoder(r)
	d.Entity = xml.HTMLEntity

	// Case 2: decoder.CharsetReader set to custom charset reader
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = customCharsetReader

	// Case 3: dec.Entity set to map literal
	dec := xml.NewDecoder(strings.NewReader("<data></data>"))
	dec.Entity = map[string]string{"foo": "bar"}

	// Case 4: xmlDecoder.CharsetReader set to charset reader
	xmlDecoder := xml.NewDecoder(r)
	xmlDecoder.CharsetReader = customCharsetReader

	// Case 5: decoder.Entity set to entity map variable
	decoder.Entity = entityMap
}
