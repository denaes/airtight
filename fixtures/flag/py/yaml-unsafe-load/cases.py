cfg = yaml.load(stream)
data = yaml.unsafe_load(fh.read())
obj = yaml.full_load(text)
cfg2 = yaml.load(open(path))
