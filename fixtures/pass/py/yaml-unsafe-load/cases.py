cfg = yaml.safe_load(stream)
data = yaml.load(stream, Loader=yaml.SafeLoader)
obj = yaml.load(text, Loader=yaml.CSafeLoader)
cfg2 = yaml.safe_load(open(path))
docs = list(yaml.safe_load_all(stream))
# yaml.load without a Loader is banned here
