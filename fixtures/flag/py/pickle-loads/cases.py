obj = pickle.loads(blob)
data = cPickle.load(fh)
up = pickle.Unpickler(fh).load()
cached = dill.loads(payload)
