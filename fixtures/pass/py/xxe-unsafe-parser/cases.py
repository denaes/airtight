tree = defusedxml.ElementTree.parse(path)
root = defusedxml.lxml.fromstring(payload)
doc = defusedxml.minidom.parseString(data)
defusedxml.sax.parse(fh, handler)
data = json.loads(payload)
# defusedxml is required for all XML input
