// False positive / near-miss cases for go/xxe-xml-decoder
package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

type Config struct {
	Entity        string
	CharsetReader string
}

func passCases(r io.Reader, w io.Writer, data []byte) {
	// Case 1: Standard decoder usage with Decode
	decoder := xml.NewDecoder(r)
	var val struct{}
	_ = decoder.Decode(&val)

	// Case 2: Commented assignment must not flag
	// decoder.Entity = xml.HTMLEntity
	// d.CharsetReader = customCharsetReader

	// Case 3: Standard xml.Unmarshal
	var doc struct{}
	_ = xml.Unmarshal(data, &doc)

	// Case 4: Standard xml.NewEncoder
	encoder := xml.NewEncoder(w)
	_ = encoder.Encode(doc)

	// Case 5: Standard decoder usage with other properties
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	d.AutoClose = xml.HTMLAutoClose
	_, _ = d.Token()

	// Case 6: Receiver name is not decoder, d, dec, or xmlDecoder
	var cfg Config
	cfg.Entity = "safe"
	cfg.CharsetReader = "utf-8"

	// Case 7: dec Token iteration without custom resolvers
	dec := xml.NewDecoder(strings.NewReader("<doc/>"))
	_ = dec.Skip()
}
