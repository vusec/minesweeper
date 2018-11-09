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
            print "Crawler running... "
            self.process = subprocess.Popen("exec " + self.cmd, shell=True) # , stdout=FNULL, stderr=FNULL
            self.process.communicate()
            #print self.process.returncode
            

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()
        print "Crawler Done "

def crawl(out, url, tm, links):
	
	if "http://" not in url and "https://" not in url:
		url = "http://" + url
	# Scale the time in milliseconds
	time = (tm)*500
	# Scale the timeout considering the number of internal links we visit
	tm = tm * links
	command = Command("node mine_crawl.js %s %s -nm -md %d -o -v -chromium -t %d" % (url, out, links, 10000 ), url)
	command.run(timeout = tm)
                        

if __name__ == "__main__":

	out = sys.argv[3]
	url = sys.argv[4]
	command = crawl(out, url, 10)
	command.run(timeout = 27)
