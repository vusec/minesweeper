#!/usr/bin/env python
# Example use
# sudo python minesweeper.py -t http://www.mejortorrent.org/ -tm 15
import subprocess
import signal
import sys
import threading
import validators
import os
import time
import json
import datetime

class Command(object):
    def __init__(self, cmd, url):
        self.cmd = cmd
        self.process = None
        self.url = url

    def run(self, timeout):
        def target():
            FNULL = open(os.devnull, 'w')
            #print ('Monitoring... ' + self.url)
            self.process = subprocess.Popen("exec " + self.cmd, stdout=FNULL, stderr=FNULL, shell=True)
            self.process.communicate()
            #print self.process.returncode
            

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            #print ('Timeout: Terminating process')
            self.process.terminate()
            thread.join()
        #print ('Monitor done!')

def get_perf_stat(stat):
	lines = stat.split("\n")
	perf = dict()
	for l in lines:
		tokens = l.split()
		if len(tokens) > 1:
			if tokens[1] == "LLC-loads":
				perf["LLC-loads"] = int(tokens[0].replace(".",""))
			if tokens[1] == "LLC-stores":
				perf["LLC-stores"] = int(tokens[0].replace(".",""))
			if tokens[1] == "L1-dcache-loads":
				perf["L1-dcache-loads"] = int(tokens[0].replace(".",""))
			if tokens[1] == "L1-dcache-stores":
				perf["L1-dcache-stores"] = int(tokens[0].replace(".",""))	
	return perf

def crawl(com, out, url, tm):

	cpufp = open(out, "w")
	# Let's begin the perf process			
	perf = subprocess.Popen(["perf","stat","-a", "-e", "LLC-loads,LLC-stores,L1-dcache-loads,L1-dcache-stores", "sleep", "5"], stderr=subprocess.PIPE)
	
	#command = Command("node mine_crawl.js %s %s -nm -nf -chromium" % (url, dumpPath), url)
	command = Command(com, url)
	command.run(timeout = tm)
                        
	# Fork the program and send the kill exit from the child to close the perf subprocess	
	if os.fork() == 0:
		# child
		time.sleep(1)
		exit(0)
	# Get the sterr output from per from the parent
	stat = perf.stderr.read().decode("utf-8")
	json.dump(get_perf_stat(stat), cpufp)
	cpufp.write('\n')
	cpufp.flush()

if __name__ == "__main__":

	com = sys.argv[2]
	out = sys.argv[3]
	url = sys.argv[4]
	command = crawl(com, out, url, 10)
	command.run(timeout = 27)
