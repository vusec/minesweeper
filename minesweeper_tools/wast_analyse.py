import sys
import re
import json
import argparse

banner = ("""
##########################################################################
##########################################################################
##  __      __          _       _                _                      ##
##  \ \    / /__ _  ___| |_    /_\   _ _   __ _ | | _  _  ___ ___  _ _  ##
##   \ \/\/ // _` |(_-<|  _|  / _ \ | ' \ / _` || || || ||_ // -_)| '_| ##
##    \_/\_/ \__,_|/__/ \__| /_/ \_\|_||_|\__,_||_| \_, |/__|\___||_|   ##
##                                                  |__/                ##
##########################################################################                                                                   
##########################################################################
A Wast functions analyser tool
""").encode('utf-8')

####################################################################
################# Global Variables declaration #####################
####################################################################

fp_cn = 'aes_keccak.txt'
path = './'
infile = []
cn = []
functions = dict()
in_loopf = dict()
unrolled_loops = None
ops = ['loop','if', 'call', 'call_indirect', 'i32.add', 'i32.sub', 'i32.mul', 'i32.div_s', 'i32.div_u', 'i32.rem_s', 'i32.rem_u', 'i32.and', 'i32.or', 'i32.xor', 'i32.shl', 'i32.shr_u', 'i32.shr_s', 'i32.rotl', 'i32.rotr', 'i32.eq', 'i32.ne', 'i32.lt_s', 'i32.le_s', 'i32.lt_u', 'i32.le_u', 'i32.gt_s', 'i32.ge_s', 'i32.gt_u', 'i32.ge_u', 'i32.clz', 'i32.ctz', 'i32.popcnt', 'i32.eqz', 'i64.clz', 'i64.ctz', 'i64.popcnt', 'i64.add', 'i64.sub', 'i64.mul', 'i64.div_s', 'i64.div_u', 'i64.rem_s', 'i64.rem_u', 'i64.and', 'i64.or', 'i64.xor', 'i64.shl', 'i64.shr_s', 'i64.shr_u', 'i64.rotl', 'i64.rotr', 'f32.add', 'f32.sub', 'f32.mul', 'f32.div', 'f32.abs', 'f32.neg', 'f32.copysign', 'f32.ceil', 'f32.floor', 'f32.trunc', 'f32.nearest', 'f32.eq', 'f32.ne', 'f32.lt', 'f32.le', 'f32.gt', 'f32.ge', 'f32.sqrt', 'f32.min', 'f32.max', 'f64.add', 'f64.sub', 'f64.mul', 'f64.div', 'f64.abs', 'f64.neg', 'f64.copysign', 'f64.ceil', 'f64.floor', 'f64.trunc', 'f64.nearest', 'f64.eq', 'f64.ne', 'f64.lt', 'f64.le', 'f64.gt', 'f64.ge', 'f64.sqrt', 'f64.min', 'f64.max']
hash_ops = ['i32.xor', 'i32.shl', 'i32.shr_u', 'i32.shr_s', 'i32.rotl', 'i32.rotr', 'i64.xor', 'i64.shl', 'i64.shr_s', 'i64.shr_u', 'i64.rotl', 'i64.rotr']
gen_crypto = None
cgraph = dict()
callstack = []
detect = dict()

##############################################################
################# General util functions #####################
##############################################################

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

#########################################################################
################# Unrolled loop detection functions #####################
#########################################################################

def extract_hash_ops(idx):
	global functions
	global hash_ops

	f_hash_ops = []
	idxs = []
	code = functions[idx]['code']

	i = 0 
	while i < len(code):
		tokens = code[i].split()
		for t in tokens:
			if t in hash_ops:
				f_hash_ops.append(t)
				idxs.append(i)
		i +=1
	return f_hash_ops, idxs

def extract_first_op(idx):
	global functions
	global hash_ops

	ops = []
	code = functions[idx]['code']

	i = 0 
	while i < len(code):
		tokens = code[i].split()
		ops.append(tokens[0])
		i +=1
	return ops

class State:
		empty = 0
		notFound = 1
		found = 2

class Seq_manager:
	seq = []
	tseq = []
	back = []
	max_len = 0
	min_seq = 0
	seq_count = 0
	state = 0

	def __init__(self,max_len, min_seq):
		self.max_len = max_len
		self.min_seq = min_seq
		self.state = State.empty
	
	def check_rep(self,seq,temp,token):
		found = False
		begin = 0
		i = 0
		while i < len(seq):
			if seq[i] == temp[i]:
				if i == len(temp) - 1:
					found = True
					break;
			else:
				if i == len(temp) - 1:
					break;
			i += 1 
		return found

	def check_rep_v(self,seq,temp,token):
		found = False
		begin = 0
		dif = len(seq) - len(temp)
		if dif < 0:
			print 'dif '+ str(dif)
			print seq
			print temp

		for i in range(dif+1):
			for idx, el in enumerate(sorted(seq)):
				if seq[idx + i] == temp[idx]:
					if idx == 0:
						begin = i + idx
					if idx == len(temp) - 1:
						found = True
						break;
				else:
					break;
				if idx == len(temp) - 1:
					break;
			if found:
				break
		if found:
			return begin
		else:
			return -1

	def append_data(self,l1,token):
		l1.append(token)

	def check_length(self,l1):
		while len(l1) > self.max_len:
			l1.pop(0)

	def print_data(self):
		print 'state: ' + str(self.state)
		print 'seq:' + str(self.seq)
		print 'tseq: ' + str(self.tseq)
		print 'count ' + str(self.seq_count)

	def check_seq(self):
		ret = None
		if self.seq_count >=self.min_seq:
			ret = dict()
			ret['seq'] = self.seq
			ret['count'] = self.seq_count + 1
		return ret

	def flush_list(self, idx, l1):
		while idx > 0:
			self.back.append(l1.pop(0))
			idx-=1

	def process_token(self,token):
		ret = None
		if self.state == State.empty:
			self.append_data(self.seq, token)
			self.state = State.notFound

		elif self.state == State.notFound:
			#If we found the element move state
			self.append_data(self.tseq, token)
			self.check_length(self.tseq)
			#self.print_data()
			while self.tseq != []:		
				found = self.check_rep_v(self.seq, self.tseq, token)
				if found != -1:
					if len(self.seq) == found + len(self.tseq):
						self.seq_count += 1
						self.tseq = []
						self.state = State.found
						self.flush_list(found, self.seq)
					break
				else:
					self.append_data(self.seq, self.tseq[0])
					self.tseq.pop(0)
					self.check_length(self.seq)

		elif self.state == State.found:
			self.append_data(self.tseq, token)
			#self.print_data()
			found = self.check_rep(self.seq, self.tseq, token)
			if found == False:
				if self.seq_count < 5:
					self.seq = self.back + self.seq*(self.seq_count+1) + self.tseq
				else:
					self.seq = self.tseq
				back = []
				self.tseq = []
				self.check_length(self.seq)
				self.state = State.notFound
				self.seq_count = 0
			if len(self.seq) == len(self.tseq):
					self.tseq = []
					self.seq_count += 1
		ret = self.check_seq()
		return ret

	#def seq_found(self):

	def get_seq(self):
		ret = dict()
		ret['seq'] = seq
		return ret

	def reset(self):
		self.state = State.notFound
		self.seq = []
		self.tseq = []
		self.seq_count = 0
		self.state = 0

def find_unrl_loops(maxlen,minrep):
	global functions
	global unrolled_loops

	unrolled_loops = dict()
	for f in functions:
		check = extract_first_op(f)
		#  TO create: Seq_manager([max sequence length],[minimum detected repetion -1 (because is from 0)])
		manager = Seq_manager(maxlen, minrep)
		old = None
		found = False
		loops = []
		i = 0
		while i < len(check):
			ret = manager.process_token(check[i])
			if ret:
				found = True
				old = ret
			else:
				if found:
					begin = i - len(old['seq'])*old['count']
					loops.append({'seq':old,'end':i, 'begin': begin })
				found = False
			i +=1;
		unrolled_loops[f] = loops

#######################################################
################# Print Functions #####################
#######################################################

def print_loops():
	global unrolled_loops

	for idx in unrolled_loops:
		print('{x} Function {idx} loops{x}'.format(x = '='*35,idx=idx))
		print "Unrolled loops: "
		print json.dumps(unrolled_loops[idx], indent=4, sort_keys=True)
		print "Loops op count"
		if idx in in_loopf: 
			print json.dumps(in_loopf[idx], indent=4, sort_keys=True)
		else:
			print "No loops"

def print_loopop_count():
	global in_loopf
	global functions
	for key in functions:
		if key in in_loopf:
			print(key)
			print(in_loopf[key])

def printfun(idx):
	global functions
	f = functions[idx]['code']
	print('{x} Function {idx} {x}'.format(x = '='*35,idx=idx))
	for l in f:
		print(l)

def printallf():
	global functions
	for key in sorted(functions):
		printfun(key)

def printf_ops(idx):
	global functions
	global ops

	f = functions[idx]
	for op in ops:
		if functions[idx][op]:
			print(op + ': ' + str(functions[idx][op]))

def printfs_ops():
	for key in sorted(functions):
		print('{x} f({idx}) operands {x}'.format(x = '='*35,idx=key))
		printf_ops(key)

def print_cgraph():
	global cgraph
	for f in sorted(cgraph):
		print('{x} f({idx}) calls {x}'.format(x = '='*35,idx=f))
		for call in sorted(cgraph[f]):
			if(call == 'call_list'):
				print('Call sequence: ' + str(cgraph[f][call]))
			else:
				print('call ' + call + ": " + str(cgraph[f][call]))

def print_cgraph_ops():
	global cgraph
	for f in sorted(cgraph):
		print('{x} f({idx}) calls {x}'.format(x = '='*35,idx=f))
		for call in sorted(cgraph[f]):
			if(call == 'call_list'):
				print('Call sequence: ' + str(cgraph[f][call]))
			else:
				print('call ' + call + ": " + str(cgraph[f][call]))
		printf_ops(f)

def print_cflow(indent, idx):
	global cgraph
	global callstack

	if indent == 0:
		print('{x} f({idx}) Call Flow {x}'.format(x = '='*35,idx=idx))
	callstack.append(idx)
	next = cgraph[idx]['call_list']

	for c in next:
		if c not in callstack:
			print('{x}-call:{n}'.format(x='\t'*indent, n=c))
			print_cflow(indent+1,c)
		else:
			print('{x}-call:{n} -->'.format(x='\t'*indent, n=c))

	callstack.remove(idx)

def print_cflows():
	saw = []
	for key in cgraph:
		for entry in cgraph[key]['call_list']:
			if entry not in saw:
				saw.append(entry)

	for key in cgraph:			
		if key not in saw:
			print_cflow(0,key)

def print_detect(detect):
	global cn

	for key in sorted(detect):
		print('{x} Best fit {idx} {x}'.format(x = '='*35,idx=key))
		print('function: {x}'.format(x = detect[key]['fname']))
		print('off: {x}'.format(x = detect[key]['off']))
		print('found_op: {x}/{totf} on {totcn}'.format(x = detect[key]['found_op'],
		totf = detect[key]['tot_onfun_op'], totcn =  detect[key]['tot_oncn_op']))
		print cn[key]

def print_detect_v(detect):
	global cn
	print detect

	for t in cn:
		print('{x} Type : {idx} {x}'.format(x = '='*35,idx=t))
		for key in sorted(cn[t]):
			print('{x} Best fit {idx} {x}'.format(x = '='*35,idx=key))
			print('function: {x}'.format(x = detect[key]['fname']))
			print('off: {x}'.format(x = detect[key]['off']))
			print('found_op: {x}/{totf} on {totcn}'.format(x = detect[key]['found_op'],
			totf = detect[key]['tot_onfun_op'], totcn =  detect[key]['tot_oncn_op']))
			print cn[t][key]
##############################################################
################# Dump on file Functions #####################
##############################################################

def save_crypto(f):
	global functions
	global fp_cn
	global path
	global hash_ops

	keccak = ['$f21']
	aes = ['$f9',  '$_aesb_single_round']
	groestl = ['$f10',  '$f13']
	skein = ['$f23',  '$f25',  '$f26']
	blake = ['$f34',  '$f17',  '$f27']

	dump_ops = dict()
#	dump_ops['keccak'] = dict()
#	dump_ops['aes'] = dict()
#	dump_ops['groestl'] = dict()
#	dump_ops['skein'] = dict()
#	dump_ops['blake'] = dict()

	for key in sorted(functions):
		temp = dict()
		name = None
		if key in keccak:
			name = 'keccak'
		if key in aes:
			name = 'aes'
		if key in groestl:
			name = 'groestl'
		if key in skein:
			name = 'skein'
		if key in blake:
			name = 'blake'
			print key
		if name != None:
			dump_ops[key] = dict()
			for op in functions[key]:
				if op in hash_ops and functions[key][op]:
					dump_ops[key][op] = functions[key][op]

	dump_on_file(path, f, dump_ops)

def save_ops(f):
	global functions
	global fp_cn
	global path
	global hash_ops

	dump_ops = dict()

	for key in sorted(functions):
		temp = dict()
		for op in functions[key]:
			if op in hash_ops and functions[key][op]:
				temp[op] = functions[key][op]
		if temp:
			dump_ops[key] = temp

	dump_on_file(path, f, dump_ops)	

def dump_detect_stats():
	global detect
	global path
	global infile
	global gen_crypto
	goodness = 0.7
	off_rate = 1
	stat = dict()
	stat['exact_fit'] = []
	stat['good_fit'] = []
	stat['bad_fit'] = []
	stat['susptect'] = []

	for key in sorted(detect):
		if  detect[key]['off'] == 0 and detect[key]['found_op'] == detect[key]['tot_oncn_op'] == detect[key]['tot_onfun_op']:
			stat['exact_fit'].append(detect[key])
		elif detect[key]['found_op'] >= goodness * detect[key]['tot_oncn_op'] and detect[key]['off'] <= off_rate * detect[key]['found_op']:
			stat['good_fit'].append(detect[key])
		#elif detect[key]['found_op'] == detect[key]['tot_oncn_op'] and detect[key]['off'] <= 3 * detect[key]['found_op']:
		#	stat['susptect'].append(detect[key])			
		else:
			stat['bad_fit'].append(detect[key])

	stat['gen_crypto'] = gen_crypto

	dump_on_file(path, infile.split("_")[1] + '.stat' ,stat)

def dump_detect_stats_v():
	global detect
	global functions
	global in_loopf
	global path
	global infile

	stat = dict()

	for key in sorted(detect):
		stat[key] = dict()
		stat[key]['detect'] = detect[key]
		stat[key]['op_f'] = dict()
		for op in functions[detect[key]['fname']]:
			if functions[detect[key]['fname']][op] > 0:
				stat[key]['op_f'][op] = functions[detect[key]['fname']][op]
		if 'loop' in stat[key]['op_f']:
			stat[key]['op_loops'] = in_loopf[detect[key]['fname']]
		else:
			stat[key]['op_loops'] = None
	r = infile.split('.')
	out = dict()
	out[r[0]] = stat
	dump_on_file(path,r[0] + '.stat' , out)

###################################################################
################# Operands counting Functions #####################
###################################################################

def count_op():
	global functions
	global ops

	for key in sorted(functions):
		f = functions[key]['code']
		for line in f:
			tokens = line.split()
			for t in tokens:
				if t in ops:
					functions[key][t] +=1

def count_ops_end(f,i,n):
	global ops
	
	flag = False
	c_list = []
	count = dict()
	ifcount = 0
	while i < len(f) and not flag:
		tokens = f[i].split()
		if 'if' in tokens:
			ifcount +=1
		if 'end' in tokens:
			if ifcount == 0:
				flag = True
				break
			else:
				ifcount -= 1
		if 'loop' in tokens:
			c, i = count_ops_end(f,i+1,n+1)
			out = dict()
			out['loop indent ' + str(n + 1)] = c
			c_list.append(c)
		tokens = f[i].split()
		for t in tokens:
			if t in ops:
				if t in count:
					count[t] += 1
				else :
					count[t] = 1
		i += 1
	out = dict()
	out['loop indent ' + str(n)] = count
	c_list.append(out)
	return c_list, i

def count_op_loop(idx):
	global functions
	f = functions[idx]['code']
	count_list = []
	in_loopf[idx] = []
	i = 0
	while i < len(f):
		if 'loop' in f[i]:
			count, i = count_ops_end(f,i+1,0)
			in_loopf[idx].append(count)
		i += 1

def count_inloops():
	global functions
	for key in functions:
		count_op_loop(key)

#################################################################
################# CFG and function detection Functions ##########
#################################################################

def find_functions(text):
	global functions
	global ops

	function = []
	f_found = False
	f_idx = None;
	for line in text:
		if re.search('\(func \([^;]*;[0-9]*;', line, re.IGNORECASE) is not None or re.search('\(func \$[^\s]*\s', line, re.IGNORECASE):
			if f_found:
				functions[f_idx.group(1)] = dict()
				functions[f_idx.group(1)]['code'] = function
				cgraph[f_idx.group(1)] = dict()
				for op in ops:
					functions[f_idx.group(1)][op] = 0
			function = [] 
			f_found = True
			f_idx = re.search('\(func \([^;]*;([0-9]*);', line, re.IGNORECASE)
			if not f_idx:
				f_idx = re.search('\(func (\$[^\s]*)\s', line, re.IGNORECASE)
		function.append(line)

def compute_cgraph():
	global functions
	global cgraph

	for key in sorted(functions):
		cgraph[key]["call_list"] = []
		for l in functions[key]['code']:
			if 'call' in l:
				res = re.findall('call ([^\)]*)[\)]*', l)
				if res:
					cgraph[key]["call_list"].append(res[0])
					if res[0] in cgraph[key]:
						cgraph[key][res[0]] +=1
					else:
						cgraph[key][res[0]] = 1

#################################################################
################# Crypto functions detection Functions ##########
#################################################################

def detect_cryptonight():
	global fp_cn
	global path 
	global functions
	global detect
	global cn

	cn = load_from_file(path,fp_cn)

	for f in sorted(cn):
		detect[f] = dict()
		bestfit = dict()
		bestfit['off'] = 700
		bestfit['found_op'] = 0
		bestfit['tot_oncn_op'] = len(cn[f]) 	#total ops in the fingerprint 
		bestfit['tot_onfun_op'] = 0 			#total ops in the analyzed function
		bestfit['fname'] = []
		for key in functions:
			off = 0
			found_op = 0
			for op in cn[f]:
				if functions[key][op] > 0:
					found_op += 1
					off += abs(functions[key][op] - cn[f][op])
			if found_op > bestfit['found_op'] or (found_op == bestfit['found_op'] and bestfit['off'] >= off + (bestfit['found_op'] - found_op)):
				bestfit['fname'] = key
				bestfit['off'] = off
				bestfit['found_op'] = found_op
				bestfit['type'] = f
				bestfit['tot_onfun_op'] = len({i:j for i,j in functions[key].items() if (j > 0 and i != 'code')})
		detect[f] = bestfit

def detect_cryptonight_v():
	global fp_cn
	global path 
	global functions
	global detect
	global cn

	cn = load_from_file(path,fp_cn)

	for f in sorted(cn):
		detect[f] = dict()
		bestfit = dict()
		bestfit['off'] = 700
		bestfit['found_op'] = 0
		bestfit['tot_oncn_op'] = len(cn[f]) 	#total ops in the fingerprint 
		bestfit['tot_onfun_op'] = 0 			#total ops in the analyzed function
		bestfit['fname'] = []
		for key in functions:
			off = 0
			found_op = 0
			for c in cn:
				for f in cn[c]:
					for op in cn[c][f]:
						if functions[key][op] > 0:
							found_op += 1
							off += abs(functions[key][op] - cn[c][f][op])
					if found_op > bestfit['found_op'] or found_op == bestfit['found_op'] and bestfit['off'] >= off + (bestfit['found_op'] - found_op) :
						bestfit['fname'] = key
						bestfit['off'] = off
						bestfit['found_op'] = found_op
						bestfit['tot_onfun_op'] = len({i:j for i,j in functions[key].items() if (j > 0 and i != 'code')})
					bestfit['type']  = c
		detect[f] = bestfit

def has_hash_op(el):
	global hash_ops

	loop_count = 0
	for key in el:
		if type(key) is dict:
			loop_count += has_hash_op(key)
		elif type(key) is list:
			for el in key:
				loop_count += has_hash_op(key)
		else:
			for k in el[key]:
				if k in hash_ops:
					loop_count += 1
					break
	return loop_count

def detect_crypto(flag):
	global functions
	global unrolled_loops
	global hash_ops
	global in_loopf
	global detect
	global gen_crypto
	loop_count = 0
	f_count = 0
	un_loops_count = 0

	for key in functions:
		found = False
		if key in in_loopf:
			for loop in in_loopf[key]:
				for el in loop:
					count = has_hash_op(el)
					if count > 0:
						found = True
						loop_count += count
		if flag:
			for el in unrolled_loops[key]:
				for op in el['seq']['seq']:
					if op in hash_ops:
						un_loops_count += 1
						found = True
						break
		if found == True:
			f_count += 1

	gen_crypto = dict()
	gen_crypto['f_count'] = f_count
	gen_crypto['loop_count'] = loop_count
	gen_crypto['loop_unr_count'] = un_loops_count

	print gen_crypto
	#TODO


	# Detect function in which are present crypto operations
	# 1. Count the hashing operations inside functions
	# 2. Count hashing operations in loops and unrolled loops
	# 3. Evaluate the probability of crypto operations 
	pass


#################################################################
########################### MAIN  ###############################
#################################################################

def wast_analysis():
	global fp_cn
	global banner
	global path
	global infile

	parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-i', '--inputfile', help="Wast input file name",metavar=('FILENAME'))
	parser.add_argument('-d','--disas', action='store_true', help="Disassemble functions code")
	parser.add_argument('-cts','--allcalltree', action='store_true', help="Print all calls")
	parser.add_argument('-ct','--calltree', help="Print call tree from the specified function", metavar=('ENTRYPOINT'))
	parser.add_argument('-ul','--unrolled_loops',type=int, nargs=2, help="Detect unrolled loops", metavar=('MAXLEN','MINREP'))
	parser.add_argument('-pl','--print_loops', action='store_true', help="Print Loops")
	parser.add_argument('-po','--print_operands', action='store_true', help="Print operands")
	parser.add_argument('-o','--dump_operands', action='store_true', help="Dump on file the operation count")
	parser.add_argument('-ac','--analyse_crypto', help="Analyse the binary for crypto functions [fingerprint input file needed]", metavar=('FINGERPRINT'))
	parser.add_argument('-os','--dump_stat', help="Dump on file the analysis statistics", metavar=('PATH'))
	parser.add_argument('-pt','--path', help="specify path", metavar=('PATH'))
	parser.add_argument('-sp','--save_fp', help="Save the fingerprint of the analysed file", metavar=('FILENAME'))

	args = parser.parse_args()
	infile = args.inputfile.split('/')
	infile = infile[len(infile) - 2] + "_" + infile[len(infile) - 1]
	f = open(args.inputfile, 'r')
	text = f.read().split('\n')

	if args.path:
		path = args.path
	# Identify and add to functions the functions
	find_functions(text)

	if args.disas:
		printallf()
		return

	# Create call graph
	compute_cgraph()

	# Explore call graph and count aritmetic operation
	count_op()
	count_inloops()
	if args.unrolled_loops:
		find_unrl_loops(args.unrolled_loops[0],args.unrolled_loops[1])

	if args.print_operands:
		print_cgraph_ops()

	if args.allcalltree:
		print_cflows()

	if args.calltree:
		if args.calltree in cgraph:
			print_cflow(0,args.calltree)
		else:
			print 'Error: now entry function with the name \'' + args.calltree + '\' was found'
			return

	if args.dump_operands:
		save_ops(args.dump_operands)

	if args.analyse_crypto:
		fp_cn = args.analyse_crypto
		detect_cryptonight()
		print_detect(detect)
		if args.unrolled_loops:
			detect_crypto(True)
		else: 
			detect_crypto(False)
		if args.dump_stat:
			path = args.dump_stat
			dump_detect_stats()
			#dump_detect_stats_v()

	if args.print_loops:
		if args.unrolled_loops:
			print_loops()
		else:
			print_loopop_count()
	if args.save_fp:
		save_crypto(args.save_fp)

if __name__== "__main__":
	wast_analysis()
