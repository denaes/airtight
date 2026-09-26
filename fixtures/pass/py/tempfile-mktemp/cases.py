fd, path = tempfile.mkstemp()
with tempfile.NamedTemporaryFile() as f: pass
d = tempfile.mkdtemp()
with tempfile.TemporaryDirectory() as d: pass
tmp = tempfile.NamedTemporaryFile(prefix="upload-", delete=False)
# mktemp is unsafe; mkstemp creates atomically
