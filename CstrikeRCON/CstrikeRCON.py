#!/usr/bin/env python2.7
# vim: sts=4 st=4 sw=4 et ai

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
                self.datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)        #This creates socket
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
                import re

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

		# tmp dictionaries
		players = dict()
		statusgame = dict()

                for i,v in enumerate(status):
                        if status[i].strip(" \t\n\r") == '':
                                continue
                        statusSplit = status[i].split(":")
                        if status[i][0] != "#" and len(statusSplit) > 1:
                                statusSplit[0] = statusSplit[0].strip(" \t\n\r")
                                statusSplit[1] = ":".join(statusSplit[1:]).strip(" \t\n\r")
                                statusgame[statusSplit[0]] = statusSplit[1]
                        else:
                                if status[i][0] == "#" and status[i] != "#      name userid uniqueid frag time ping loss adr":
                                        """
                                            Example out:
                                            '#       name           userid  uniqueid             frag time        ping loss adr'
                                            '# 1     "Fessgun"      206     STEAM_0:0:405427330  -1   27:29       9    0    94.137.223.108:27005', 
                                            '# 2     "[zbot] Stone" 212     BOT                  15   27:18:02    0    0',
 					    '# 1     "Yo"           474     VALVE_ID_LAN         8    15:19       8    0    94.137.199.3:27005'
                                        """

                                        playerArr = re.compile(r'^#\s+(?P<number>\d+)\s+(?P<name>".*")\s+(?P<userid>\d+)\s+(?P<uniqueid>\S+)\s+(?P<frag>-\d+|\d+)\s+(?P<time>\d\d:\d\d:\d\d|\d\d:\d\d)\s+(?P<ping>\d+)\s+(?P<loss>\d+)(?P<addr>.*|)$')
                                        playerDict = [m.groupdict() for m in playerArr.finditer(status[i])][0]

                                        playerName = playerDict['name']
                                        players[playerName] = playerDict

                # prettify data for status dict
                playerCount = re.compile(self.rgx["player_count"]).findall(statusgame["players"])
                mapInfo = statusgame["map"].split(":")
                map = re.compile(self.rgx["map"]).findall(mapInfo[0])[0]
                coords = list(re.compile(self.rgx["map_coords"]).findall(mapInfo[1])[0])
                statusgame["name"] = statusgame["hostname"]

                tcpIP = statusgame["tcp/ip"].split(":")
                if len(tcpIP) > 1:
                    statusgame["ip"] = tcpIP[0]
                    statusgame["port"] = tcpIP[1]
                else:
                    statusgame["ip"] = tcpIP[0]
                    statusgame["port"] = 'None'

                statusgame["map"] = map
                statusgame["coords"] = coords
                statusgame["players"] = "/".join(playerCount[0])

                del statusgame["hostname"]
                del statusgame["tcp/ip"]

                return {"status": statusgame, "players": players}

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
