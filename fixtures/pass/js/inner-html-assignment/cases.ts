el.textContent = userContent;
el.innerHTML = "";
el.innerHTML = "<hr>";
node.innerHTML = DOMPurify.sanitize(html);
el.append(document.createTextNode(name));
const html = sanitizeHtml(raw);
