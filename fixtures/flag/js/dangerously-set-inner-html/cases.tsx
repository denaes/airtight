<div dangerouslySetInnerHTML={{ __html: body }} />
return <span dangerouslySetInnerHTML={{ __html: post.content }} />;
props.dangerouslySetInnerHTML = { __html: raw };
<article dangerouslySetInnerHTML={{ __html: markdown }} />
