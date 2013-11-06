#!/usr/bin/python

""" CstrikeRCON: An HLDS1-based Cstrike servers RCON querying library """
""" fully tested with Counter-Strike 1.6 (unit test included [test.py]) """

__author__    = "Alex Vanyan"
__copyright__ = "Copyright 2013 alex-v.net"
__version__   = "1.0.1"
__status__    = "First Release"


# exceptions...

# base rcon exception type
class RCON_Exception(Exception):
	def __init__(self, message):
		self.message = message
	def __str__(self):
		return str(self.message)

class RCON_NoConnectionException(RCON_Exception):
	pass

class RCON_NoPacketReceivedException(RCON_Exception):
	pass

class RCON_BadPasswordException(RCON_Exception):
	pass

class RCON_DataFormatMismatchException(RCON_Exception):
	pass

class RCON_NoChallengeException(RCON_Exception):
	pass

class RCON_NoStatusException(RCON_Exception):
	pass


# dependencies...
import socket
import re

class CstrikeRCON:
	_instance = None

	# class member variables
	RCONchallenge = None
	RCONpasswd = None
	status = {}
	players = {}
	rgx = {
		"challenge": "challenge\srcon\s(\d+)",
		"rcon_passwd_fail": "Bad\srcon_password",
		"status": "hostname.+\x00",
		"player_count": "(\d+)[^\d]+(\d+)",
		"map": "^[^\s]+",
		"map_coords": "(\d+)\sx[^\d]+(\d+)\sy[^\d]+(\d+)\sz"
	}

	# singleton'ize the class
	def __new__(cls, *args, **kwargs):
		if not cls._instance:
			cls._instance = super(CstrikeRcon, cls).__new__(cls, *args, **kwargs)
		return cls._instance

	# open datagram socket at class initialization stage
	def __init__(self, host, port=27015, passwd=""):
		self.sockinfo = (host, port)
		self.RCONpasswd = passwd
		self.datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	#This creates socket
		self.datagram.settimeout(2.0)
		if not self.datagram:
			raise RCON_NoConnectionException("Could not connect to the cstrike server")

	# get rcon challenge id
	def getChallenge(self):
		challenge = self.dispatchDatagram("challenge rcon").receiveDatagram("challenge")
		if challenge and challenge[0].isdigit():
			return int(challenge[0])
		else:
			raise RCON_NoChallengeException("Could not get RCON challenge")
	
	def getServerInfo(self):
		if not self.RCONchallenge:
			try:
				self.RCONchallenge = self.getChallenge()
			except RCON_NoChallengeException as e:
				return str(e)
		passwd = str(self.RCONpasswd)
		passwdStr = ' "' + passwd + '"' if passwd else ""
		status = self.dispatchDatagram("rcon " + str(self.RCONchallenge) + passwdStr + " status").receiveDatagram("status")
		self.closeSocket()
		status = "\n".join(status).strip("\xFF\x00").split("\n")
		startPlayers = False
		for i,v in enumerate(status):
			if status[i].strip(" \t\n\r") == '':
				continue
			statusSplit = status[i].split(":")
			if status[i][0] != "#" and len(statusSplit) > 1:
				statusSplit[0] = statusSplit[0].strip(" \t\n\r")
				statusSplit[1] = ":".join(statusSplit[1:]).strip(" \t\n\r")
				self.status[statusSplit[0]] = statusSplit[1]
			else:
				if status[i][0] == "#":
					playerArr = filter(None, [x.strip() for x in status[i][1:].split(" ")])
					if not startPlayers:
						self.playerPattern = playerArr
						startPlayers = True
					else:
						playerName = playerArr[1][1:-1]
						playerPattern = self.playerPattern[1:]
						self.players[playerName] = {}
						self.players[playerName]["id"] = int(playerArr[0])
						for i,v in enumerate(playerPattern):
							self.players[playerName][v] = playerArr[2 + i];
						# prettify data for players dict
						tcpIP = self.players[playerName]["adr"].split(":")
						self.players[playerName]["ip"] = tcpIP[0]
						self.players[playerName]["port"] = tcpIP[1]
						self.players[playerName]["frags"] = self.players[playerName]["frag"]
						del self.players[playerName]["adr"]
						del self.players[playerName]["frag"]
		# prettify data for status dict
		tcpIP = self.status["tcp/ip"].split(":")
		playerCount = re.compile(self.rgx["player_count"]).findall(self.status["players"])
		mapInfo = self.status["map"].split(":")
		map = re.compile(self.rgx["map"]).findall(mapInfo[0])[0]
		coords = list(re.compile(self.rgx["map_coords"]).findall(mapInfo[1])[0])
		self.status["name"] = self.status["hostname"]
		self.status["ip"] = tcpIP[0]
		self.status["port"] = tcpIP[1]
		self.status["map"] = map
		self.status["coords"] = coords
		self.status["players"] = "/".join(playerCount[0])
		del self.status["hostname"]
		del self.status["tcp/ip"]
		return {"status": self.status, "players": self.players}

	def checkRconPasswd(self, data):
		rgx = re.compile(self.rgx["rcon_passwd_fail"])
		if type(data) == list:
			data = "".join(data)
		find = rgx.findall(data)
		if find and len(find) > 0:
			raise RCON_BadPasswordException("Rcon password is wrong")

	# generic request builder
	def buildRequest(self, request):
		initBytes = "\xFF\xFF\xFF\xFF"
		finalBytes = "\n"
		return initBytes + request + finalBytes

	def receiveDatagram(self, expect):
		# start reading from UDP socket
		while 1:
			try:
				data, addr = self.datagram.recvfrom(1024)
			except socket.timeout:
				raise RCON_NoPacketReceivedException("Timeout trying to receive data")
			else:
				if expect != "challenge":
					self.checkRconPasswd(data)
				find = re.compile(self.rgx[expect], re.DOTALL).findall(data)
				if len(find) > 0:
					return find
				else:
					raise RCON_DataFormatMismatchException("RCON protocol data format may have Mismatch")
	
	def dispatchDatagram(self, data):
		self.datagram.sendto(self.buildRequest(data), self.sockinfo)
		return self
			
	def closeSocket(self):
		self.datagram.close()
		return self
