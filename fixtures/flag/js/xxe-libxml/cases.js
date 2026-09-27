const doc1 = libxmljs.parseXml(xmlString, { noent: true });
const doc2 = libxml.parseXmlString(input, { noent: true });
const doc3 = parseXml(xml, { noent: true, nonet: false });
const doc4 = libxmljs.parseXml(data, { noent: true });
const doc5 = parseXmlString(userXml, { dtdload: true, noent: true });
const doc6 = libxmljs2.parseXml(rawXml, { noent: true });
const doc7 = libxml.parseXml(payload, { recover: true, noent: true });
