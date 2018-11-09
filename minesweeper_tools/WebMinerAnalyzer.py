#!/usr/bin/env python

# python WebMinerAnalyzer.py www.mejortorrent.org ./data 10

import requests
import json
import sys
import os
import subprocess
import time
import json
import re
import time as t
import shutil
import datetime
import magic
import run_web
import util
import pdb

fil = ['chatbro','tidio.co', 'getcourse.ru', 'bitcoin.com', 'streamlegends.com', 'thankyou.ru', 'rtschannel.com', 'ekranet.com', 'betgamestv.eu', 'camlinq', 'sciaga.pl', 'lockerdome', 'drivezy.com', 'realtime', 'wattbike.com', 'chatwee-api', 'mixer.combotframework.com', 'pusherapp.com', 'kf5.com', 'upscope.io', 'netpeak.cloud', 'curachat.com', 'channel.io', 'livecall.io', 'help.com', 'csgotower.com', 'siteheart.com', 'flyzoo.co', 'synerise.com', 'retain.ir', 'comagic.ru', 'sbtech.com', 'revechat.com', 'truconversion.com', 'forexpros.com', 'byside.com', 'raychat.io', 'deezer.com', 'velaro.com', 'freshrelevance.com', 'inside-graph.com', 'thelivechatsoftware.com', 'onicon.ru', 'czater.pl', 'mycertifiedservice.com', 'rafflecopter.com', '5p4rk13.com', 'active.com', 'alloka.ru', 'aml.ink', 'angelthump.com', 'bgrndi.com', 'cadlearning.com', 'cdnmedia.tv', 'clipinteractive.com', 'convertfox.com', 'csgotrinity.com', 'dealerfire.com', 'destiny.gg', 'episodecalendar.com', 'fifa55u.com', 'footyroom.com', 'hdkinoshka.net', 'lentainform.com', 'livehouse.in', 'lokspeedarma.com', 'lori.ru', 'luxadv.com', 'mixcloud.com', 'native.ai', 'ogaming.tv', 'overrustle.com', 'pancernik.info', 'poooo.ml', 'recreativ.ru', 'repl.it', 'scholastic.com', 'skinhub.com', 'skinup.gg', 'smashcast.tv', 'sochi.camera', 'stocktwits.com', 'straitstimes.com', 'tass.ru', 'tf.rs', 'tvrain.ru', 'viafoura.io', 'vtsmedia.com', 'whatsthescore.com', 'wigzopush.com', 'bugaboo.tv', 'codio.com', 'comode.kz', 'gocdn.ru', 'goshow.tv', 'iflychat.com', 'kuchebraska.com', 'luxup.ru', 'maxizone.win', 'megacdn.ru', 'poorchat.net', 'pregame.com', 'rambler.ru', 'spriteclub.tv', 'suptv.org', 'swarmcdn.com', 'teenslang.su', 'vbrick.com', 'vs3.com', 'bncapp.net', 'jmvstream.com', 'reg.place', 'streamable.com', 'universenetwork.tv', 'wotcase.ru', 'zohopublic.eu', 'vwd-webtech.com', 'geckodev.eu', 'fsdatacentre.com', 'ustream.tv', 'skalhuset.se', 'cleversite.ru', 'naiadsystems.com', 'bcrncdn.com', 'sketchboard.me', 'hotjar.com', 'jivosite.com', 'zohopublic.com', 'visitors.live', 'drift.com', 'crisp.chat', 'mieru-ca', 'hypercomments', 'herokuapp.com', 'giosg.com', 'easybroadcast.fr', 'cloudup.com', 'engine.io', 'FastcastService', '/app/', 'rltracker.pro', 'paintcollar', 'zenrus.ru', 'walls.io', 'spots.im', 'replain.cc', 'smartsupp', 'tunegenie', 'appcues', 'nexus', 'padlet.com', 'ws_client?customer', 'levelupmedia', 'twitch', 'chatango', 'p2pnow', 'banomago', 'rizotina', 'chessbase', 'goodgame', 'wsm', 'wsp', 'dditscdn', 'highwebmedia', 'realtime', 'exitgames', '33across.com', 'cbox', 'bet365affiliates', 'peer5', 'inspectlet', 'tradingview', 'chatbro', 'tawk', 'firebaseio', 'zopim', 'livestream', 'streamroot', 'cackle', 'chess24', 'foes', 'amap', 'feedjit', 'bpasyspro', 'agarioforums', 'intercom', 'webspectator', 'botframework.com']

patterns = {
	'js' : 'cryptonight|WASMWrapper|crytenight|load.jsecoin.com|hash_cn',
	'wasm' : b'\x00\x61\x73\x6d',
	'rwasm' : '.wasm|.wasl|.wsm',
	'ppool' : ".pool.:.([A-Za-z0-9\.]+).,.login",
	'login' : ".login.:.([A-Za-z0-9]+).,.password",
	'ws' : '\"type\":\"job\",\"params\":|\"type\":\"auth\",\"params\":|\"type\":\"submit\",\"params\":|\"type\":\"authed\",\"params\":|\"identifier\":\"job\"|\"identifier\":\"handshake\",\"pool\"|\"command\":\"connect\"|\"command\":\"work\"|\"command\":\"share\"|\"command\":\"\"accepted\"|\"command\":\"info\"|\"command\":\"get_job\"|\"command\":\"set_cpu_load\"|\"command\":\"set_job\"',
	'pool' : "\[WS-Creation\](.*)",
}
# 13 known services initial dataset
patterns_types_ini = {
	'coinhive' : "new CoinHive\.Anonymous|coinhive.com/lib/coinhive.min.js|authedmine.com/lib/",  
	'cryptonoter' : "minercry.pt/processor.js|\.User\(addr",  
	'nfwebminer' : "new NFMiner|nfwebminer.com/lib/",  
	'jsecoin' : "load.jsecoin.com/load",  
	'webmine' : "webmine.cz/miner",  
	'cryptoloot' : "CRLT\.anonymous|webmine.pro/lib/crlt.js|verifier.live/lib/crypta.js",   
	'coinimp' : "www.coinimp.com/scripts|new CoinImp.Anonymous|new Client.Anonymous|freecontent.stream|freecontent.data|freecontent.date",  
	'deepminer' : "new deepMiner.Anonymous|deepMiner.js",
	'monerise' : "apin.monerise.com|monerise_builder",
	'coinhave' :'minescripts\.info',
	'cpufun' :'snipli.com/[A-Za-z]+\" data-id=',
	'minr' : 'abc\.pema\.cl|metrika\.ron\.si|cdn\.rove\.cl|host\.dns\.ga|static\.hk\.rs|hallaert\.online|st\.kjli\.fi|minr\.pw|cnt\.statistic\.date|cdn\.static-cnt\.bid|ad\.g-content\.bid|cdn\.jquery-uim\.download',
	'mineralt' : 'ecart\.html\?bdata=|/amo\.js\">|mepirtedic\.com',
}

patterns_types = {
	'coinhive' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		'fp': "coinhive"}, 
	'cryptonoter' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "var addr = .([A-Za-z0-9]+)|\.Anonymous\(.([A-Za-z0-9]+)",
		 'fp': "cryptonoter|\.User\(addr"},  
	'nfwebminer' : { 'ws_key': ".hash.:.([A-Za-z0-9]+).,.hostname",
		 'script_key': "NFMiner(.([A-Za-z0-9]+)",
		 'fp': "nfminer"},  
	'jsecoin' : { 'ws_key': None,
		 'script_key': "https://load\.jsecoin\.com/load/([0-9]+)/",
		 'fp': "jsecoin"},  
	'webmine' : { 'ws_key': "api.:.([A-Za-z0-9]+)",
		 'script_key': "https://webmine\.cz/miner\?key=([A-Za-z0-9]+)",
		 'fp': "webmine\.cz"},  
	'cryptoloot' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': "crlt\.anonymous|cryptoloot"},  
	'cryptominer' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': "mrwayne|CH.Anonymous"},  
	'coinimp' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': "coinimp|freecontent.stream|freecontent.data"},  
	'deepminer' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': "deepminer"},
	'monerise' : { 'ws_key': "/proxy/\?pa=([A-Za-z0-9]+)",
		 'script_key': "monerise_payment_address=.([A-Za-z0-9]+)",
		 'fp': "monerise"},
	'coincube' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'CoinCube'},
	'grindcash' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'ulnawoyyzbljc\.ru'},
	'coinhave' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'minescripts\.info'},
	'kuku' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'KUKU\.Anonymous'},
	'cpufun' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'snipli.com/[A-Za-z]+\" data-id='},
	'minr' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'cnt\.statistic\.date|cdn\.static-cnt\.bid|ad\.g-content\.bid|cdn\.jquery-uim\.download'},
	'ricewithchicken' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'cricewithchicken\.js|RiseCrackerWrapper|datasecu.download|jqcdn.download'},
	'connection' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'interestingz\.pw|unconvulsed\.com|srvs\.stream|unrummaged\.com|artedite\.com|hhb123\.tk'},
	'mineralt' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'ecart\.html\?bdata=|/amo\.js\">|mepirtedic\.com'},
	'dryptonight' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'CTWASMWrapper|dryptonight|drivecdn.com'},
	'blakcrypto' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': 'blakcrypto\.com'},
	'generic' : { 'ws_key': ".site_key.:.([A-Za-z0-9]+).,.type",
		 'script_key': "\.Anonymous\(.([A-Za-z0-9]+)|\.User\(.([A-Za-z0-9]+)|var addr = .([A-Za-z0-9]+)",
		 'fp': None} 
}


def start_chromium():
	os.system('chromium-browser --headless --no-sandbox --remote-debugging-port=9222 &')

def kill_chromium():
	subprocess.check_call(["pkill", "chromium-browse"])

def init_min_detect():

	min_detect = dict()
	min_detect = dict()
	min_detect['js'] = False
	min_detect['js_root'] = False
	min_detect['wasm'] = False
	min_detect['rwasm'] = False
	min_detect['cpu'] = 0
	min_detect['nblob'] = 0
	min_detect['blob_root'] = False
	min_detect['ws_present'] = False
	min_detect['ws_root'] = False
	min_detect['ws'] = False
	min_detect['html'] = []
	min_detect['ws_obf'] = False
	min_detect['root'] = False
	return min_detect

def extend_min(min_detect):
	miner_webs = dict()
	miner_webs['key'] = [] 
	miner_webs['pool'] = []
	miner_webs['js'] = min_detect['js']
	miner_webs['wasm'] = min_detect['wasm']
	miner_webs['cpu'] = min_detect['cpu']
	miner_webs['nblob'] = min_detect['nblob']
	miner_webs['type'] = list(min_detect['html'])
	miner_webs['ws'] = min_detect['ws']
	miner_webs['ws_obf'] = min_detect['ws_obf']
	miner_webs['ws_pres'] = min_detect['ws_present']
	miner_webs['js_root'] = min_detect['js_root']
	miner_webs['ws_root'] = min_detect['ws_root']
	miner_webs['blob_root'] = min_detect['blob_root']
	miner_webs['ppool'] = []
	miner_webs['login'] = []
	return miner_webs

def load_files(url_path):
	files = []
	for (dirpath, dirnames, filenames) in os.walk(url_path):
		files.extend(filenames)
		return files

def detect_from_file(path, files, pattern):
	for file in files:
		file_path = path + '/' + file
		try:
			f = open(file_path,'r')
			text = f.read().replace('\n', '')
			if re.search(pattern, text, re.IGNORECASE) is not None:
				return True
		except Exception as e:
			print "[!] Couldn't read file " + file_path
			print str(e)
	return False

def detect_cpu(path, file):
	try:
		cpu_path = path + '/' + file
		cpu_file = open(cpu_path, 'r')
		#Get Line with most cpu usage
		cpu_max = 0
		for line in cpu_file:
			tokens = line.split();
			if float(tokens[3]) > cpu_max:
				cpu_max = float(tokens[3])
	except Exception as e:
		print "[!][S2] No Cpu file for " + cpu_path
		print str(e)
		return -1

	return cpu_max

def count_blob(url_path, file):
	try:
		path = url_path + '/' + file
		rfile = open(path, 'r')
		text = rfile.read()
		return text.count('ATTACHED')	  
	except Exception as e:
		print "[!][S2] (can happen) No service workers file file for " + path
		return -1

def step_2(path, web, min_detect):
	global patterns
	global patterns_types_ini

	requests = 'requests'
	cpu_usage = 'cpuUsage'
	ws_dump = 'WSdump'
	htmlpage = 'full.html'
	sworkers = 'serviceworkes'

	web_path = os.path.join(path,web).split(":")[0]
	js_found = False
	wasm_found = False
	html_found = False
	for url in next(os.walk(web_path))[1]:
			
		url_path = os.path.join(web_path, url)
		files = load_files(url_path)

		#Detect Worker code in miners
		if not js_found:
			js_found = detect_from_file(url_path, files, patterns['js'])
			min_detect['js'] = js_found
			if js_found and url == '[esc]':
				min_detect['js_root'] = True

		#Detect wasm
		if not wasm_found:
			wasm_found = detect_from_file(url_path, files, patterns['wasm'])
			min_detect['wasm'] = wasm_found

		#Detect Orchestrator code in miners
		if not html_found:
			files = [htmlpage]
			for t in patterns_types_ini:
				html_found = detect_from_file(url_path, files, patterns_types_ini[t])
				if html_found and t not in min_detect['html']:
					min_detect['html'].append(t)

		#Check if request contain wasm

		if not min_detect['rwasm']:
			files = [requests]
			min_detect['rwasm'] = detect_from_file(url_path, files, patterns['rwasm'])

		nblob = count_blob(url_path, sworkers);
		if nblob >  min_detect['nblob']:
			if url == '[esc]':
				min_detect['blob_root'] = True
			min_detect['nblob'] = nblob

		#Detect Cpu load
		max_cpu = detect_cpu(url_path, cpu_usage)
		if min_detect['cpu'] < max_cpu:
			min_detect['cpu'] = max_cpu

		#Detect WS comunications
		if not min_detect['ws']:
			files = [ws_dump]
			if (os.path.exists(url_path + '/' + ws_dump)):
				min_detect['ws_present'] = True
				if url == '[esc]':
					min_detect['ws_root'] = True
				if(magic.from_file(url_path + '/' + ws_dump) == 'data'):
					min_detect['ws_obf'] = True
				min_detect['ws'] = detect_from_file(url_path, files, patterns['ws'])

	return min_detect

def step3(path, miner_webs, web):
	global patterns_types
	global patterns_types_ini

	# Get the right web path
	web_path = os.path.join(path, web).split(":")[0]
	found_type = []

	# If no type was detect try again:
	if miner_webs['type'] == []:
		# Load Files	   
		for url in next(os.walk(web_path))[1]:
			url_path = os.path.join(web_path, url)
			files = load_files(url_path)

			# Look for types fingerprints matches
			for file in files:
				file_path = os.path.join(url_path, file)
				try:
					f = open(file_path,'r')
					text = f.read()
					for t in patterns_types:
						if t not in found_type and t not in patterns_types[t]['fp'] and t not in patterns_types_ini and re.findall(patterns_types[t]['fp'], text, re.IGNORECASE):
							miner_webs['type'].append(t)
							found_type.append(t)
				except Exception as e:
					print "[!] Couldn't read file " + file_path
					print str(e)

	# If not types matches are found mark it as generic
	if not miner_webs['type']:
		miner_webs['type'].append('generic')			 
	#Dump the results in the folder in json
	return miner_webs

def step4(path, miner_webs, web):
	ws_dump = 'WSdump'
	htmlpage = 'full.html'
	global patterns
	global patterns_types

	web_path = os.path.join(path, web).split(":")[0]

	  
	# Load Files		
	for url in next(os.walk(web_path))[1]:
		url_path = os.path.join(web_path, url)

		# 1. If WS try to extract key and pool
		try:
			f = open(os.path.join(url_path, ws_dump),'r')
			text = f.read()

			# Get public pools and login
			res = re.findall(patterns['ppool'], text, re.IGNORECASE)
			for r in res:
				if r not in miner_webs['ppool']:
					miner_webs['ppool'].append(r)
			res = []
			res = re.findall(patterns['login'], text, re.IGNORECASE)
			for r in res:
				if r not in miner_webs['login']:
					miner_webs['login'].append(r)
			res = []

			# Get keys
			for t in miner_webs['type']:
				if patterns_types[t]['ws_key']:
					res = re.findall(patterns_types[t]['ws_key'],
							text, re.IGNORECASE)
					for r in res:
						if r not in miner_webs['key']:
							miner_webs['key'].append(r) 
			# Get pool address  
			res = re.findall(patterns['pool'],
				text, re.IGNORECASE)
			for r in res:
				if r not in miner_webs['pool']:
					miner_webs['pool'].append(r)

		except Exception as e:
			print("key and pool detection: " + str(e))

		# Special case for jsecoin
		if 'jsecoin' in miner_webs['type']:
			try:
				f = open(os.path.join(url_path, htmlpage),'r')
				text = f.read()
				res = re.findall(patterns_types['jsecoin']['script_key'],
						text, re.IGNORECASE)
				for r in res:
					if r not in miner_webs['key']:
						miner_webs['key'].append(r)
			except Exception as e:
				print("key and pool jse coin detection: " + str(e))

		# 2. If (1.) failed try to extract key from js	  
		if not miner_webs['key'] and miner_webs['js']:
			try:
				f = open(os.path.join(url_path, htmlpage),'r')
				text = f.read()
				for t in miner_webs['type']:
					res = re.findall(patterns_types[t]['script_key'],
							text, re.IGNORECASE)
					for r in res:
						if r not in miner_webs['key']:
							miner_webs['key'].append(r)
			except Exception as e:
				print("key from js detection: " + str(e))


	return miner_webs

def filter_rm_pools(data): 
	global fil
	if data['pool']:
		for p in data['pool']:
			if any(x in p for x in fil):
				data['pool'].remove(p)
	return data
def print_profile(data):
	'''
	{
		"blob_root": false, 
		"cpu": 127.88643533122735, 
		"js": false, 
		"js_root": false, 
		"key": [
			"37efd635d0ec154de4d0b17dd1952aa3b5e88acd6bbe"
		], 
		"login": [], 
		"nblob": 16, 
		"pool": [
			" wss://sea.reauthenticator.com/", 
			" wss://sass.reauthenticator.com/"
		], 
		"ppool": [], 
		"type": [
			"cryptoloot"
		], 
		"wasm": true, 
		"ws": true, 
		"ws_obf": false, 
		"ws_pres": true, 
		"ws_root": false
	}
	'''
	print "CPU: %.2f" %(data['cpu'])
	print "Mining payload: " + str(data['js'])
	print "Miners from root page: " + str(data["js_root"])
	print "Public pool: " + str(data["ppool"]) + " with login id " + str(data["login"])
	print "Pool proxy: " + str(data["pool"])
	print "Matching type: " + str(data["type"])
	print "Open WebSocket: " + str(data["ws_pres"]) + " - Obfuscated: " + str(data["ws_obf"])
	print "Stratum communication: " + str(data["ws"])
	print "Service workers: " + str(data["nblob"])

def crawl_and_profile(target, out, time, links):

	if not os.path.exists(out):
		os.makedirs(out)
###############################################################################
#					   Crawl phase
###############################################################################
# We first want to crawl the website

	print "Launched the crawler! "
	start_chromium()
	t.sleep(2)
	run_web.crawl(out, target, time, links)
	kill_chromium()

###############################################################################
#					   Analisis phase
###############################################################################
# Then we want to enrich the data


# Step 1: check crawl status
	crawl_succ = False

	try:
		status = open(os.path.join(out, status_f),'r')
		lines = status.read().splitlines()
		for l in lines:
			if "Crawl-complete" in l:
				crawl_succ = True
				break
	except Exception as e:
		print "[!][S1] Can't find previous output"
		print e

	if not crawl_succ:
		print "[!] Couldn't reach the host " + target 
		print "[!] Exiting... "
		sys.exit()

	# Step 2
	print "Step 2"
	min_detect = init_min_detect()
	min_detect = step_2(out, target, min_detect)

	min_detect = extend_min(min_detect)

	# Step 3: 
	print "Step 3"
	min_detect = step3(out, min_detect, target)
	
	# Step 4: 
	print "Step 4"
	data = step4(out, min_detect, target)

###############################################################################
#					   Detection phase
###############################################################################
# Finally we want to detect if the website is a miner
	# Remvove whitelisted websocket connections from pool
	data = filter_rm_pools(data)


	# Pretty print JSON

	shutil.rmtree(os.path.join(out,""))

	return data

# Names
status_f = "status"

if __name__ == "__main__":
	try:
		target = sys.argv[1]
		out = sys.argv[2]
		time = int(sys.argv[3])
		links = int(sys.argv[4])
	except:
		print "Usage: python ./WebMinerAnalyzer.py [TARGET WEB] [OUT PATH] [CRAWL TIMEOUT] [INTERNAL LINKS]\n"\
				"Example: python WebMinerAnalyzer.py www.coinhive.com ./data 10 3"
		sys.exit()
	data = crawl_and_profile(target, out, time, links)
	print json.dumps(data, indent=4, sort_keys=True)

	if (((data['js']) or data['key']!= [] or (data['type'] != [] and data['type'][0] != 'generic')) and data['ws_pres'] and data['nblob'] > 0) or data['ws'] or data['ppool'] or data['login']:
	   print "[*] Miner found!"
	elif data['ws_pres'] and data['nblob'] > 0 and data['cpu']>50 and data['pool']:
		print "[*] Found WS and high cpu and service workers"
	elif data['ws_pres'] and data['cpu']>50:
		print "[*] Found WS and high cpu"
	else:
		print "[*] No Miner found"

