import json


def dump_on_file(path, file, data):
	try:
		f = open(path + file, 'w')
		json.dump(data,f)
		f.close()
		return 1
	except Exception as e:
		print "[!] Can't dump on file output: " + path + file
		print e
		return 0

def load_from_file(path, file):
	try:
		f = open(path + file, 'r')
		data = json.load(f)
		f.close()
		return data
	except Exception as e:
		print "[!] Can't load from file: " + path + file
		print e
		return None
