const doc1 = libxmljs.parseXml(xmlString, { noent: false });
const doc2 = libxmljs.parseXml(xmlString);
xml2js.parseString(xml, (err, result) => handle(result));
// libxmljs.parseXml called with default options (noent defaults to false)
const doc3 = parseXmlString(xml, { nonet: true, noent: false });
const parsed = fastXmlParser.parse(xmlData);
const doc4 = libxml.parseXmlString(input);
