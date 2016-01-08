#!/usr/bin/python

import sys
from CstrikeRCON.CstrikeRCON import *
from pprint import pprint

"""
	Unit test for CstrikeRCON
	execute from command line: ./test.py
"""

host = "127.0.0.1" if len(sys.argv) < 2 else sys.argv[1]
passwd = None if len(sys.argv) < 3 else sys.argv[2]

if __name__ == "__main__":
	try:
                cstrikeRCON = CstrikeRCON(host, passwd=passwd)
                pprint(cstrikeRCON.getServerInfo())
	except RCON_Exception as e:
		print type(e), ":", e.message
	except Exception as e:
		print "Uncaught exception:", str(e)
		print "Have you specified arg1 (server hostname/IP) and arg2 (RCON password) from command line?"
