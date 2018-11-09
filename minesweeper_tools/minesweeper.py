#!/usr/bin/env python

# Example use
# sudo python minesweeper.py -t https://thepiratebay.org -tm 15

import sys
import os
import json
import argparse
import util
import run
import shutil
import md5
import validators
import math
import WebMinerAnalyzer

from termcolor import colored


banner = ("""
################################################################################
################################################################################                                                
		 _____ _         _____                           		
		|     |_|___ ___|   __|_ _ _ ___ ___ ___ ___ ___ 		
		| | | | |   | -_|__   | | | | -_| -_| . | -_|  _|		
		|_|_|_|_|_|_|___|_____|_____|___|___|  _|___|_|  		
		                                    |_|          		
################################################################################                                                                   
################################################################################
A WebMiners advanced detection tool
""").encode('utf-8')

config_file = "config.json"
dir_path = os.path.dirname(os.path.realpath(__file__))
config = []
default_time = 10

if __name__ == "__main__":

###############################################################################
#						Setup phase
###############################################################################
	parser = argparse.ArgumentParser(description=banner, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-t', '--target', help="Targer URL to analyse",metavar=('TARGET'))
	parser.add_argument('-ws','--wasm_analysis', action='store_true', help="Only Wasm analysis")
	parser.add_argument('-mn','--monitor', action='store_true', help="Only CPU event monitor")
	parser.add_argument('-tm','--time', help="Specify the time to monitor (1-30 sec)",metavar=('TIME'))

	args = parser.parse_args()
	print banner

	target = ""
	# Check if the provided arguments are correct
	die = False
	message = ""
	if not args.target:
		die = True
		message = "No target argument provided: -t [TARGET URL]"
	else:
		target = args.target
		if "http://" not in target:
			target = "http://" + target
		if not validators.url(target):
			die = True
			message = "The target url is malformed: " + args.target

	if not os.path.isfile( os.path.join(dir_path, config_file)):
		die = True
		message = "No configuration file found: " + os.path.join(dir_path, config_file)

	if args.time:
		if not args.time.isdigit():
			die = True
			message = "Time specified not numeric"
		elif float(args.time) > 30 or float(args.time) < 1:
			die = True
			message = "Time specified to small or too large"

	config = util.load_from_file(os.path.join(dir_path,""),config_file)
	if not config:
		die = True
		message = "The configuration file is malformed"

	# TODO check whether the configuration dictionary contains the right data

	if die:
		print message
		sys.exit()
	
	time = default_time
	if args.time:
		time  = float(args.time)

	print "URL Target: " + colored(target, 'cyan') + " Visiting for " + colored(str(time),'cyan') + " sec"
###############################################################################
#						Stage 1: Website analysis
###############################################################################

	if not os.path.exists(config['out']):
	    os.makedirs(config['out'])

	print "[S1] Website Analysis..."
	
	md5_target = md5.new(target).hexdigest()
	outwasm = os.path.join(config['out'], md5_target)
	cpu_stat_f = os.path.join(config['out'], md5_target + ".txt")

	if not os.path.exists(outwasm):
	    os.makedirs(outwasm)

	#./chrome-build/chrome coinhive.com --no-sandbox --js-flags="--dump-wasm-module --dump-wasm-module-path=./data"
	command = config['chrome'] + ' ' + target + \
		' --no-sandbox --js-flags="--dump-wasm-module --dump-wasm-module-path=' + outwasm + '"'
	run.crawl(command, cpu_stat_f , target, time)

###############################################################################
#						Stage 2: Wasm analysis
###############################################################################
	wasm_f = ""
	stat_f = ""

	print "[S2] Looking for a wasm module..."
	for fname in os.listdir(outwasm):
		if fname.endswith('.wasm'):
			# do stuff on the file
			wasm_f = fname
			break

	if not wasm_f:
		print "[S2] No Wasm module found... Moving to S4"
		print "[>] Hint: try to increase the timeout -tm [seconds]"
	else:
		print "[S2] Wasm module found: " + wasm_f
		wasm_path = os.path.join(outwasm, wasm_f)
		wast_path = wasm_path[:-1] + "t"

		print "[S2] Wasm to Wast decoding..."
		# Create wast from wasm
		ret = os.system("{wabt} {name} -o {out}".format(wabt = config['wabt'], \
			name = wasm_path, out = wast_path))

		# Analyse the wasm
		print "[S2] Wast analysis..." 
		if os.path.isfile(wast_path):
			print "[S2] Created Wast file: " + wast_path.split("/")[-1]
			stat_f = wast_path + ".stat" 
			ret = os.system("python {analyse} -i {file} -ac {fp} -os {out}" \
				" -ul 25 4 > /dev/null 2>&1".format(analyse = config["wast_analyse"], file = wast_path, \
					fp = config["fingerprint"], out = os.path.join(outwasm, "")))
		else:
			print "[!] The collected wasm samples is broken\n"

###############################################################################
#						Stage 3: Crypto primitives detection
###############################################################################
	stats = None
	gen_crypto = False
	cn_crypto = False
	primitives = config["fp_function_count"]

	if stat_f:
		print "[S3] Analysing Wast results..."
		stats = util.load_from_file("",stat_f)
	if stats:
		#Check for generic crypto
		if stats['gen_crypto']['f_count'] > 5 and stats['gen_crypto']['loop_count'] \
			+ stats['gen_crypto']['loop_unr_count'] > 10:
			gen_crypto = True

		for k in stats['bad_fit']:
			if 	k['found_op'] == k['tot_oncn_op'] and k['off'] <= 2 * k['found_op']:
				stats['bad_fit'].remove(k)
				stats['suspect'].append(k)
			else:
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
		cn = 0
		for k in primitives:
			if primitives[k] == 0:
				cn += 1

		if cn < math.ceil(float(config["fp_function_types"]))/2:
			cn_crypto = True
	else:
		print "[!] The wasm analysis file output is missing or malformed"
		


###############################################################################
#						Stage 4: Website profile
###############################################################################
	target_web = target.replace('http://',"")
	target_web = target_web.replace("/", "")
	data = WebMinerAnalyzer.crawl_and_profile(target_web, "data_crawl", 10, 3)

	print "{hash}\n{x}Results:{x}\n{hash}\n".format(hash = "#"*80,x = " "*35)
	if (((data['js']) or data['key']!= [] or (data['type'] != [] and data['type'][0] != 'generic')) and data['ws_pres'] and data['nblob'] > 0) or data['ws'] or data['ppool'] or data['login']:
		print colored("[*] Miner found!", 'red') 

###############################################################################
#						Report results
###############################################################################

	print "Website Profile:"
	WebMinerAnalyzer.print_profile(data)
	print ""
	sys.stdout.write("Detection from profile:\t\t\t")	
	if (((data['js']) or data['key']!= [] or (data['type'] != [] and data['type'][0] != 'generic')) and data['ws_pres'] and data['nblob'] > 0) or data['ws'] or data['ppool'] or data['login']:
		print colored("POSITIVE", 'green')
	else:
		print colored("NEGATIVE", 'red')

	sys.stdout.write("General crypto activity:\t\t")
	if gen_crypto:
		print colored('POSITIVE', 'green') 
	else:
		print colored('NEGATIVE', 'red')
	sys.stdout.write("CryptoNight Algorithm Detected:\t\t")
	if cn_crypto:
		print colored('POSITIVE', 'green') 
	else:
		print colored('NEGATIVE', 'red')

	shutil.rmtree(os.path.join(config['out'],""))
