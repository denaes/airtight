tree = xml.etree.ElementTree.parse(path)
root = etree.fromstring(payload)
doc = minidom.parseString(data)
sax.parse(fh, handler)
