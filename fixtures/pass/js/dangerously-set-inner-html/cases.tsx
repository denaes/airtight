<div>{body}</div>
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />
<span>{post.content}</span>
const html = sanitizeHtml(raw);
<article>{markdown}</article>
// dangerouslySetInnerHTML is avoided throughout this file
