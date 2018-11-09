import sys
import os
import json
import util
from shutil import copyfile

def easy():
	in_file = sys.argv[1]
	path = './wasmcrawled/'
	f = open(in_file, 'r')
	text = f.read().split('\n')
	out = './collected/'
	count = 1
	for t in text:
		tokens = t.split('/')
		out_p = out + tokens[-2] + '_' + tokens[-1]
		#print "Prog: " + str(count)
		count += 1
		wast = t[2:-1] + 't'
		t = path + t[2:]
		try:
			if os.path.exists(path + wast):
				print tokens[-2] + "\t" + tokens[-1]
				copyfile(t,out_p)
		except:
			pass#print "Can't copy: " + t

def main():
	in_file = sys.argv[1]
	path = './unique/'
	f = open(in_file, 'r')
	text = f.read().split()
	out = './statunique/'
	stats = dict()
	count = 0
	allf = 0
	for t in text:
#		if count > 1:
#			break
		allf +=1
		wasm = t[:]
		if 'wasm' in wasm:
			wast = wasm[:-1] + 't'
			t = path  + wast
		else:
			wast = wasm + '.wast'
			t = path  + wast
#		ret = os.system("../wabt/bin/wasm2wat {name} -o {out}".format(name = path + wasm, out = t))
#		if os.path.isfile(t):
#			count+=1
#		else:
#			print "bad: " + t
		print "wast of " + str(count) + " on " + str(allf)

		print 'Analyzing ' + t
#		if os.path.isfile(t):
#			ret = os.system("python ./wast_analyse.py -i {file} -ac cn_fingerprint.txt -os {out} -ul 25 4".format(file = t, out = out))
#		count += 1

	if len(sys.argv) > 2:
		files = [f for f in os.listdir(out)]
		tot_found = dict()
		tot_found_prim = dict()
		type_counter = dict()
		tot = 0
		general_count = 0
		general_neg = 0 
		general_neg_name = []

		for file in files:
			tot += 1
			stats[file] = load_from_file(out,file)

		for key in stats:
			# Count the general crypto detection
			if stats[key]['gen_crypto']['f_count'] > 5 and stats[key]['gen_crypto']['loop_count'] + stats[key]['gen_crypto']['loop_unr_count'] > 10:
				general_count += 1
			else:
				print key.split('_')[0]
				general_neg += 1
				general_neg_name.append(key)

		for key in stats:
			primitives = {'keccak': 2, 'blake':3 , 'aes': 2, 'groestl': 2, 'skein': 3}

			stats[key]['suspect'] = []
			for k in stats[key]['bad_fit']:
				if 	k['found_op'] == k['tot_oncn_op'] and k['off'] <= 2 * k['found_op']:
					stats[key]['bad_fit'].remove(k)
					stats[key]['suspect'].append(k)
					print key + " " + str(k)
				#Count the number of the functions bad calssified
			for k in stats[key]['bad_fit']:
				if 'type' in k:
					if 'keccak' in k['type']:
						primitives['keccak'] -=1
					if 'blake' in k['type']:
						primitives['blake'] -=1
					if 'aes' in k['type']:
						primitives['aes'] -=1
					if 'groestl' in k['type']:
						primitives['groestl'] -=1
					if 'skein' in k['type']:
						primitives['skein'] -=1
			count_prim = 0
			which_prim = []

			if not stats[key]['exact_fit'] and not stats[key]['good_fit'] and not stats[key]['suspect']:
				primitives['keccak'] = primitives['blake'] = primitives['aes'] = primitives['groestl'] = primitives['skein'] = 0

			for k in primitives:
				if primitives[k] == 0:
					count_prim += 1
					which_prim.append(k)

#			if count_prim == 2:
#s				print "XXXXX: " +  key
			if str(count_prim) in tot_found:
				tot_found[str(count_prim)] += 1
			else:
				tot_found[str(count_prim)] = 1

			if str(count_prim) not in tot_found_prim:
				tot_found_prim[str(count_prim)] = []

			for prim in which_prim: 
				if prim not in tot_found_prim[str(count_prim)]:
					if type(tot_found_prim[str(count_prim)]) != dict:
						tot_found_prim[str(count_prim)] = dict()
					tot_found_prim[str(count_prim)][prim] = 1
				else: 
					tot_found_prim[str(count_prim)][prim] += 1

			#Count the type of the functions bad calssified		
			for k in stats[key]['bad_fit']:
				if 'type' in k and k['type'] in type_counter:
					type_counter[k['type']] += 1
				elif 'type' in k:
					if k['type'] == 'aes2':
						print key
					type_counter[k['type']] = 1
				else:
					if 'null' not in type_counter:
						type_counter['null'] = 1
					type_counter['null'] +=1 

		# Print the results
		print "Total analyzed samples: " + str(tot)
		print json.dumps(tot_found, indent=4, sort_keys=True)
		print json.dumps(tot_found_prim, indent=4, sort_keys=True)
		print json.dumps(type_counter, indent=4, sort_keys=True)
		
		print "General pos: " + str(general_count)
		print "General Neg " + str(general_neg)
		print general_neg_name
if __name__== "__main__":
	main()
#	easy()