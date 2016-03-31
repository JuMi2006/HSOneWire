# -*- coding: iso8859-1 -*-
## -----------------------------------------------------
## Logik-Generator  V1.9
## -----------------------------------------------------
## Copyright © 2010, knx-user-forum e.V, All rights reserved.
##
## This program is free software; you can redistribute it and/or modify it under the terms
## of the GNU General Public License as published by the Free Software Foundation; either
## version 3 of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
## without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
## See the GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along with this program;
## if not, see <http://www.gnu.de/documents/gpl-3.0.de.html>.

### USAGE:  python.exe LogikGenerator.py [--debug --en1=34 --en2="TEST"]
### python.exe 12969_HSOneWire.py


import sys
import os
import base64 
import marshal
import re
import md5
import inspect
import time
import random
import socket
import tempfile
import popen2
import zlib
import zipfile

##############
### Config ###
##############

## Name der Logik
VERSION="V0.01"
LOGIKNAME="HSOneWire"
## Logik ID
LOGIKID="12969"

## Ordner im GLE
LOGIKCAT="OneWire"


## Beschreibung
LOGIKDESC="""
Bausteinbeschreibung hier ...

E1=IP-Adresse des Rechners auf dem der owserver läuft.
E2=Konfiguration (port,cycle,debug,lang)
E3=pass
E4=direkte Pfadangabe: 26.13D96B010000/VDD
E5=Lizenzcode

A1=Test 
A2=pass
A3=Lizenzinformationen
A4=pass
A5=pass
A6=pass / Systemlog XML (NilsS) Ausgang
"""



## Bedingung wann die kompilierte Zeile ausgeführt werden soll
BEDINGUNG="OC[1] or EI"
## Formel die in den Zeitspeicher geschrieben werden soll
ZEITFORMEL=""
## Nummer des zu verwenden Zeitspeichers
ZEITSPEICHER="0"

## UPDATE: Nicht mehr relevant
## AUF True setzen um Binären Code zu erstellen
doByteCode=False
#doByteCode=True

## UPDATE: Nicht mehr relevant
## Base64Code über SN[x] cachen
doCache=False

## Doku erstellen Ja/Nein
doDoku=True

debug=False
livedebug=False

showList=False
#############################
########## Logik ############
#############################
LOGIK = '''# -*- coding: iso8859-1 -*-
## -----------------------------------------------------
## '''+ LOGIKNAME +'''   ### '''+VERSION+'''
##
## erstellt am: '''+time.strftime("%Y-%m-%d %H:%M")+'''
## -----------------------------------------------------
## Copyright © 2010, knx-user-forum e.V, All rights reserved.
##
## This program is free software; you can redistribute it and/or modify it under the terms
## of the GNU General Public License as published by the Free Software Foundation; either
## version 3 of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
## without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
## See the GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along with this program;
## if not, see <http://www.gnu.de/documents/gpl-3.0.de.html>.

## -- ''' +re.sub("\n","\n## -- ",LOGIKDESC)+ ''' 

#5000|"Text"|Remanent(1/0)|Anz.Eingänge|.n.|Anzahl Ausgänge|.n.|.n.
#5001|Anzahl Eingänge|Ausgänge|Offset|Speicher|Berechnung bei Start
#5002|Index Eingang|Default Wert|0=numerisch 1=alphanummerisch
#5003|Speicher|Initwert|Remanent
#5004|ausgang|Initwert|runden binär (0/1)|typ (1-send/2-sbc)|0=numerisch 1=alphanummerisch
#5012|abbruch bei bed. (0/1)|bedingung|formel|zeit|pin-ausgang|pin-offset|pin-speicher|pin-neg.ausgang

5000|"'''+LOGIKCAT+'''\\'''+LOGIKNAME+'''"|0|4|"E1 IP-Addresse"|"E2 Config"|"E3 leer"|"E4 Pfad/Test"|5|"A1 Debug"|"A2 pass|"A3 pass"|"A4 pass"|"A5 Systemlog XML"|"'''+VERSION+'''"

5001|4|5|2|2|1

# EN[1]
##* IP-Addr des OneWireServer
5002|1|"192.168.2.223"|1
# EN[2]
##* Config  ## Werte mit * trennen. Mögliche Werte: port
5002|2|"lang=de*port=4304"|1
# EN[3]
##* Senden  ##
5002|3|""|1
# EN[4]
##* Senden  ## 
5002|4|""|1


# Speicher
##* Klassenspeicher
5003|1||0  
5003|2|''|0  

# Ausgänge
##* Debug
5004|1|""|0|1|1 
##* pass
5004|2|""|0|1|1
##* pass
5004|3|""|0|1|1
##* pass
5004|4|""|0|1|1
##* Systemlog-XML
5004|5|""|0|1|1

#################################################
'''

#####################
#### Python Code ####
#####################
code=[]


## 0 = Base64 mit Quelltextlisting
## 1 = Base64 ohne Quelltext
## 2 = ByteCode mit zlib komprimiert ohne Quelltext
code.append([1,"EI","""
if EI:
    ## um auch DNS nutzen zu können
    global socket
    import socket
    if not hasattr(socket,"_hs_dnsresolver"):
        ## alltes getaddrinfo speichern
        socket._socket_getaddrinfo = socket.getaddrinfo
        ## den HS internen Resolver an das socket Modul binden
        socket._hs_dnsresolver = self.MC.DNSResolver.getHostIP
        ## neue getaddrinfo Funktion
        def _hsgetaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0): 
            return socket._socket_getaddrinfo(socket._hs_dnsresolver(host),port, family,socktype,proto,flags)
        ## und die alte gegen die neue ersetzen
        socket.getaddrinfo = _hsgetaddrinfo
	
	## Class for 1-Wire-Communication
	global ow_comm
	class ow_comm():	
		def __init__(self,host,port):
			print "init ow_connection"
			self.host = host
			self.port = port
			self.flag = 0x00000100   # ownet
			self.flag += 0x00000004  # persistence
			self.flag += 0x00000002  # list special directories
			self._socket = []
						
		def _connect(self,socknum=0):
			try:
				print self._socket
				print socknum
				self.sleep(1)
				## TCP-Socket erstellen
				self._socket.append(__import__('socket').socket(__import__('socket').AF_INET,__import__('socket').SOCK_STREAM))
				print self._socket
				self.sleep(1)
				## Verbinden
				print "Connect to OneWire-Server " + self.host + ":" + str(self.port) + " socket number #" + str(socknum) 

				self.sleep(1)
				self._socket[socknum].connect((self.host,self.port))
				self.log('Verbindung hergestellt','info')
				print "set timeout"
				self.sleep(1)
				self._socket[socknum].settimeout(10) 
				print "connected[]"
				self.sleep(1)
				self.connected.append(True)
				return True
	
			except __import__('socket').error:
				print "Can't connect to OneWire-Server "+self.host+":"+str(self.port)
				self.log('Verbindung fehlgeschlagen','warning')
				self.connected[socknum] = False
				return False
				
			except:
				###DEBUG###
				__import__('traceback').print_exc(file=__import__('sys').stdout)
				###DEBUG###
				print "Connection Lost to OneWire-Server "+self.host+":"+str(self.port)
				self.log('Verbindung verloren','warning')
				self.connected[socknum] = False
				return False	
					
		def presence(self, socknum, path):
			return self._request(socknum, path, function=6)
				
		def read(self, socknum, path):
			return self._request(socknum, path, function=2)
			
		def write(self,socknum, path, value):
			return self._request(socknum, path, function=3)
			
		def dir(self, socknum, path='/'):
			return self._request(socknum, path, function=9)
	
		def int_from_bytes(self, b): 
			return (((((int(b[3]) << 8) + int(b[2]) << 8) + int(b[1])) << 8) + int(b[0]))
			
		def _request(self, socknum, path, function, value=None):
			self._lock = __import__('threading').Lock()
			with self._lock:
				payload = path + __import__('struct').pack('B', 0)
				data = 65536
			
				### BUILD HEADER ###
				### http://owfs.org/index.php?page=owserver-protocol
					# to Server Fixed header	
					# version		*assure protocol compatibility		*4-byte network order
					# payload		*length (in bytes) of payload data	*4-byte network order
					# type			*type of function call				*4-byte network order
					# control_flags *format flags						*4-byte network order
					# size			*size of data element (read/write)	*4-byte network order
					# offset	 	*offset for read/write				*4-byte network order
					# var. payload	*variable length raw data
				header = __import__('struct').pack('IIIIII',
					__import__('socket').htonl(0),				# version
					__import__('socket').htonl(len(payload)),		# payload length
					__import__('socket').htonl(function),			# message type
					__import__('socket').htonl(self.flag),		# format flags
					__import__('socket').htonl(data),				# size of data element read/write
					__import__('socket').htonl(0))					# offset read/write
				
				### SEND MESSAGE TO SERVER ###
				#print self.connected
				#print self._socket
				#print "socknum: " + str(socknum)
				#print "stat at request connected: " + str(self.connected[socknum])

				try:
					if not self.connected[socknum]:
						print "try to connect"
						self._connect(socknum)
				except IndexError:
					print "try to connect"
					self._connect(socknum)
					
				try:
					self._socket[socknum].sendall(header + payload)
				except Exception, e:
					print "socket send error: "
					print e
					self.close(socknum)	
					
				### RECIEVE ANSWER ###
				#print "sendout - now recieve"

				while True:  # ignore ping packets
					try:
						header = self._socket[socknum].recv(24)
						#print "Header-Len:" + str(len(header))
					except __import__('socket').timeout:
						print "socket timeout error"
					except Exception, e:
						self.close(socknum)
						print "socket recv error:"
						print e
					if len(header) != 24:
						print "header error"
						return
					
					header = __import__('struct').unpack('IIIIII', header)
					header = map(__import__('socket').ntohl, header)
					
					# to Client Fixed header	
					# version		*assure protocol compatibility		00:04 *4-byte network order
					# payload		*length (in bytes) of payload data	04:08 *4-byte network order
					# type			*type of function call				08:12 *4-byte network order
					# control_flags *format flags						12:16 *4-byte network order
					# size			*size of data element (read/write)	16:20 *4-byte network order
					# offset	 	*offset for read/write				20:44 *4-byte network order
					# var. payload	*variable length raw data
			
					fields = ['version', 'payload', 'type', 'ctrl_flags', 'size', 'offset']
					header = dict(zip(fields, header))
			
					#print header['version']
					#print header['payload']
					#print header['type']
					#print header['ctrl_flags'] #http://owfs.org/index.php?page=owserver-flag-word
					#print header['size']
					#print header['offset']
					
					if not header['payload'] == 4294967295: #0xFFFFFFFF = Ping Packet
						break		
				
				# case: path not found
				if header['type'] == 4294967295: #0xFFFFFFFF = Not Found Path ?
			
					###CHECK FOR IBUTTONS ONLY VIA PRESENCE
					if function == 6: #just check presence and sensor was not found
						return False
					else:
						print "path unknown: " + path
					
				if header['type'] == 4294967275: #0xFFFFFFEB = Found Path ?
					print "path found: " + path
				
				# case: zero/empty payload
				if header['payload'] == 0:
					print "payload zero: " + path
			
				### READ PAYLOAD ###
				try:
					payload = self._socket[socknum].recv(header['payload']) #Read length of Payload from Socket
			
					###CHECK FOR IBUTTONS ONLY VIA PRESENCE
					if function == 6: #just check presence and sensor was found
						self.id = ''
						for i in range(len(payload)-1):
							_hex = hex(__import__('struct').unpack('B',payload[i])[0])
							_hex = _hex[2:] #remove first 0x
							_hex = _hex.upper() #upper
							if len(_hex) == 1:
								_hex = '0' + _hex #adding leading zero
							if i == 0:
								self.id += str(_hex) + '.'
							else:
								self.id += str(_hex)
						#print self.id
						if self.id in path:
							return True
							
				except __import__('socket').timeout:
					print "socket timeout error"
				except Exception, e:
					self.close(socknum)
					print "socket recv error in read payload:"
					print e
				
				### CHECK/SORT/FORMAT PAYLOAD ###
				if not header['payload'] - 1 == header['size']: #FIXME
					pass
					#print "ERROR"
					#return
				#check for "/" in Payload ??????
				if payload.startswith('/'):
					return payload.strip(__import__('struct').pack('B', 0)).split(',')
				else:
					payload = payload.strip() #Leerzeichen entfernen
					if payload.replace('.', '').isdigit():
						return float(payload)
					else:
						return payload
		
		def close(self,socknum):
			try:
				self._socket[socknum].close()
				self.connected[socknum] = False
				print "Socket closed"
			except:
				print "Error in closing socket"			
		
    global knxuf_hs_onewire_connector
    class knxuf_hsonewire_connector(ow_comm):
		def __init__(self, local, host, configstr):
			self.logik = local.get("pItem")
			self.MC = self.logik.MC
			#self.get_ikos() ## passende ikos finden
			self.lock = __import__('threading').Lock()
			self.host = host
			self.__myLogID=__import__('md5').new(str(__import__('random').random())).hexdigest()
			
			######################
			#### START KONFIGURATION
			######################
			## Hier einfach mögliche Konfigs rein die an EN[2] sein können
			## Zugriff über dict: self._config['lang'] = 'de'
			self._config = {'lang':'de','port':4304,'cycle':120,'debug':0}
			## das wertet die Konfig aus
			self.setConfig(configstr)
			##Debug laden
			try:
				self.debug = self._config['debug']
			except KeyError:
				## Default - No Debug
				self.debug = 0
			##Cycle laden
			try:
				self.cycle=float(self._config['cycle'])
			except KeyError:
				## Default behalten
				self.cycle=float(120)
			######################
			#### ENDE KONFIGURATION
			######################			


			######################
			#### START DEFINITION EIGENER OBJEKTE
			######################
			##self.mydict = {'keyword1':value1,'keyword2':value}
			
			#self.tm = {'ID of DA18B20':['type':'DS18B20','temperature':Temperatur], 'ID of DS2401':['type':'DS2401','status':True/False,'last_seen':float(time())], 'ID of DS2438':['type':'DS2428','temperature':Temperatur,'humidity':Feuchtigkeit,'VDD':VDD,'VAD':VAD,'vis':Helligkeit]}
			self.tm = {}
			self.last_cycle = 0
			self.bus = []
			self.global_sensors = {} # ID:type
			self.onewire_ikos = {}
			self._socket = []
			self.connected = []
			
			######################
			#### ENDE DEFINITION EIGENER OBJEKTE
			######################		

			## Start des Threads
			ow_comm.__init__(self,self.host,4304)
			self.__runit=True
			self.start_thread()
		
		def now(self):
			return __import__('time').time()
		
		def sleep(self,s):
			__import__('time').sleep(s)
		
		### wait
		def __wait(self,socknum):
			while self.__runit:
				if self.connected[socknum]:
					if self.last_cycle == 0:
						self.last_cycle = self.now()
					elif self.last_cycle + float(self.cycle) < self.now():
						self.refresh(socknum)
						self.last_cycle = self.now()
					else:
						#print "wait 1 second for cycle-check"
						self.sleep(10)
						
					pass
							
		### Das ist die Funktion die immer als Thread läuft
		def __loop(self):
			print "start loop"
			socknum = 0
			print "socknum in loop"
			sleeptime = []
			## Verbindungs restartzeiten
			self.restartSleepTime = [ 10,10,20,30,30,30,60,120,180,300 ]
			while True:
				## hier die Verbindung aufbauen
				self._connect(socknum)
				if self.connected[socknum]:
					sleeptime = self.restartSleepTime
					try:
						self.log("Start Loop",'debug')
						self.discovered = False
						self.discover(socknum)
						self.__wait(socknum)
					finally:
						print "Closing Socket"
						self.close(socknum)
				else:
					if len(sleeptime) == 0:
						## Wenn keine Werte mehr im Verbindungstimeout sind, verwende den letzten Eintrag (hier 300sek)
						stime = self.restartSleepTime[-1]
					else:
						## immer den ersten Wert als Timeout nehmen und aus der liste entfernen
						stime = sleeptime.pop(0)
					self.sleep(stime)
					
		def start_thread(self):
			## die Funktion __loop als Thread ausführen
			self.__thread = __import__('threading').Thread(target=self.__loop,name='OneWire_'+self.host)
			self.__thread.setDaemon(True)
			print "Start Thread"
			self.__thread.start()

		def _ibutton_thread(self):
			print "################ START IBUTTON THREAD ######################"
			self.my_buttons = ['01.28F8B0150000','01.A655B0150000'] #Nur zum Test fest codiert
			self.busmaster_id = ['bus.1'] #Pfad zum Busmaster (uncached !)
			self._ib_thread = __import__('threading').Thread(target=self._ibutton_loop,name='ibutton_loop')
			self._ib_thread.setDaemon(True)
			self._ib_thread.start()

		def _ibutton_loop(self):
			_ibutton_socknum = 1
			self.__lock = __import__('threading').Lock()
			with self.__lock:
				while True:
					if self.discovered:
						found = []
						for bus_id in self.busmaster_id:
							path = '/uncached/' + bus_id + '/'
							bus_sensors = self.dir(_ibutton_socknum,path)
							#print bus_sensors
								
							for sensor in bus_sensors:
								sensor = sensor[11+len(bus_id):][:-1] ### FIXME TO REGEX
								found.append(sensor)
								
							#TEST REGEX
							for sensor in bus_sensors:
								import re
								_regex = re.compile("([0-9a-fA-F]{2}.)([0-9a-fA-F][0-9a-fA-F]{6})")
								_match = _regex.search(sensor)
								if _match:
									print _match
						#print found
						for button in self.my_buttons:
							try:
								if button in found:
									state = True
								else:
									state = False
								self.log(str(button) + ' ' + str(state),'debug')
								_dict = {'status':state,}
								if state:
									_dict.update({'last_seen':self.now()})
								self.tm[button].update(_dict)
								print self.tm[button]
							except KeyError:
								print "iButton never seen ?"
							except Exception, e:
								print e
						self.sleep(0.5)
			
		def _ibutton_loop2(self):  # NOT USED AT MOMENT
			_ibutton_socknum = 1
			self.__lock = __import__('threading').Lock()
			with self.__lock:
				while True:
					if self.discovered:
						for button in self.my_buttons:
							try:
								state = self.presence(_ibutton_socknum,'/uncached/' + button + '/locator')
								#print state
								self.log(str(button) + ' ' + str(state),'debug')
								_dict = {'status':state,}
								if state:
									_dict.update({'last_seen':self.now()})
								self.tm[button].update(_dict)
								print self.tm[button]
							except KeyError:
								print "iButton never seen ?"
							except Exception, e:
								print e
						self.sleep(0.5)

		def _io_thread(self):
			print "################ START IO THREAD ######################"
			self.my_ios = ['3A.E7290D000000','3A.1B320D000000','3A.96280D000000'] #Nur zum Test fest codiert
			self._io_thread = __import__('threading').Thread(target=self._io_loop,name='io_loop')
			self._io_thread.setDaemon(True)
			self._io_thread.start()
					
		def _io_loop(self):
			_io_socknum = 2
			self.__lock = __import__('threading').Lock()
			with self.__lock:
				while True:
					if self.discovered:
						for sensor in self.my_ios:
							try:
								#print "PIO"
								pio_a = self.read(_io_socknum,'/uncached/' + sensor + '/PIO.A')
								pio_b = self.read(_io_socknum,'/uncached/' + sensor + '/PIO.B')
								sensed_a = self.read(_io_socknum,'/uncached/' + sensor + '/sensed.A')
								sensed_b = self.read(_io_socknum,'/uncached/' + sensor + '/sensed.B')
								self.log(str(sensor) + ' ' + str(pio_a),'debug')
								self.log(str(sensor) + ' ' + str(pio_b),'debug')
								self.log(str(sensor) + ' ' + str(sensed_a),'debug')
								self.log(str(sensor) + ' ' + str(sensed_b),'debug')
								
								_dict = {'pio_a':pio_a , 'pio_b':pio_b , 'sensed_a':sensed_a , 'sensed_b':sensed_b}
								
							except Exception, e:
								print e
								
							if self.tm.has_key(sensor):
								self.tm[sensor].update(_dict)
							else: 
								self.tm.update({sensor:_dict})
							self.sleep(1)
							
		def _typematch(self,_id,__dict): # NOT USED AT MOMENT
			self.__lock = __import__('threading').Lock()
			with self.__lock:
				
				for id,dict in self.tm.items():
					if id == _id:
						print "Altes: " + str(dict)
						print "Ergän: " + str(__dict)
						dict.update(__dict)
					print "Neues: " + str (self.tm[_id])
					
				try:
					if self.tm[_id]['sensor_type'] in ['DS2401']:
						#print self.tm[_id]
						try:
							if __dict['status'] != self.tm[_id]['status']:
								print "Status of " + _id + " changed to " + str(__dict[_id]['status'])
						except Exception, e:
							print e
					elif self.tm[_id]['sensor_type'] in ['DS18B20','DS18S20','DS2438']:
						#print self.tm[_id]
						try:
							if __dict['temp'] != self.tm[_id]['temp']:
								print "Temperature of " + _id + " changed to " + str(__dict[_id]['temp'])
						except Exception, e:
							print e
					elif self.tm[_id]['sensor_type'] in ['DS2438']:
						#print self.tm[_id]
						try:
							if __dict['vis'] != self.tm[_id]['vis']:
								print "Vis of " + _id + " changed to " + str(__dict[_id]['vis'])
							elif __dict['hum'] != self.tm[_id]['hum']:
								print "Humidity of " + _id + " changed to " + str(__dict[_id]['hum'])
							elif __dict['vad'] != self.tm[_id]['vad']:
								print "VAD of " + _id + " changed to " + str(__dict[_id]['vad'])
							elif __dict['vdd'] != self.tm[_id]['vdd']:
								print "VDD of " + _id + " changed to " + str(__dict[_id]['vdd'])
						except Exception, e:
							print e
				except KeyError:
					print "not scanned yet"
				except Exception, e:
					print "Exception in typematch"
					print e


		#################################
		#### START OWSERVER ROUTINEN ####
		#################################
					
		def refresh(self,socknum):
			for sensor, sensor_type in self.global_sensors.items():
				self.sleep(0.5)
				if sensor_type in ['DS18B20','DS18S20']: #Temperatur/Multisensor
					#read temperature
					#print 'scan: read temperature of ' + sensor_type + ' ' + sensor
					temp = self.read(socknum,'/uncached/' + sensor + '/' + 'temperature')
					#print str(temp) + ' Grad'
					self.log(str(sensor) + ' ' + str(temp),'debug')
					
					_dict = {'temp':temp , 'sensor_type':sensor_type}

				if sensor_type in ['DS2438']: #Multisensor
					#read temperature
					#print 'scan: read temperature of ' + sensor_type + ' ' + sensor
					temp = self.read(socknum,'/uncached/' + sensor + '/' + 'temperature')
					#print str(temp) + ' Grad'
					self.log(str(sensor) + ' ' + str(temp),'debug')
					#read humidity
					#print 'scan: read   humidity  of ' + sensor_type + ' ' + sensor
					hum = self.read(socknum,'/uncached/' + sensor + '/' + 'HIH4000/humidity')
					#print str(hum) + ' rF'
					self.log(str(sensor) + ' ' + str(hum),'debug')
					#read vis
					#print 'scan: read     vis     of ' + sensor_type + ' ' + sensor
					vis = self.read(socknum,'/uncached/' + sensor + '/' + 'vis')
					if vis > 0:
						vis = round(10 ** ((float(vis) / 47) * 1000))
					else: #13
						value = 0
					#print str(vis) + ' Lux'
					self.log(str(sensor) + ' ' + str(vis),'debug')
					#read VDD
					#print 'scan: read     VDD     of ' + sensor_type + ' ' + sensor
					vdd = self.read(socknum,'/uncached/' + sensor + '/' + 'VDD')
					#print str(vdd) + ' Volt'
					self.log(str(sensor) + ' ' + str(vdd),'debug')
					#read VAD
					#print 'scan: read     VAD     of ' + sensor_type + ' ' + sensor
					vad = self.read(socknum,'/uncached/' + sensor + '/' + 'VAD')
					#print str(vad) + ' Volt'
					self.log(str(sensor) + ' ' + str(vad),'debug')
					
					_dict = {'temp':temp , 'hum':hum , 'vis':vis , 'vdd':vdd , 'vad':vad , 'sensor_type':sensor_type}
					
				if sensor_type in ['DS2401']: #iButton
					#read iButton
					#print 'scan: read   iButton   of ' + sensor_type + ' ' + sensor
					ibutton = self.presence(socknum,'/uncached/' + sensor)
					#print str(ibutton) + ' iButton'
					
					_dict = {'status':ibutton , 'sensor_type':sensor_type}
					
				if sensor_type in ['DS2413', 'DS2406']:#IO
					#read PIO.A
					#print 'scan: read    PIO.A    of ' + sensor_type + ' ' + sensor
					pio_a = self.read(socknum,'/uncached/' + sensor + '/' + 'PIO.A')
					#print str(pio_a) + ' PIO.A'
					#read PIO.B
					#print 'scan: read    PIO.B    of ' + sensor_type + ' ' + sensor
					pio_b = self.read(socknum,'/uncached/' + sensor + '/' + 'PIO.B')
					#print str(pio_b) + ' PIO.B'
					#read sensed.A
					#print 'scan: read  sensed.A   of ' + sensor_type + ' ' + sensor
					sensed_a = self.read(socknum,'/uncached/' + sensor + '/' + 'sensed.A')
					#print str(sensed_a) + ' sensed.A'
					#read sensed.B
					#print 'scan: read  sensed.B   of ' + sensor_type + ' ' + sensor
					sensed_b = self.read(socknum,'/uncached/' + sensor + '/' + 'sensed.B')
					#print str(sensed_b) + ' sended.B'
					
					_dict = {'pio_a':pio_a , 'pio_b':pio_b , 'sensed_a':sensed_a , 'sensed_b':sensed_b , 'sensor_type':sensor_type}
				
				if sensor_type in ['DS1420']:#Busmaster
					pass
			
				if self.tm.has_key(sensor):
					self.tm[sensor].update(_dict)
				else: 
					self.tm.update({sensor:_dict})
					
		def discover(self,socknum):
			print "start discovery"
			try:
				dir_list = self.dir(socknum,'/')
			except Exception, e:
				print e
				return
	
			if type(dir_list) != list:
				print "dir is not a list ?"
				return
			for path in dir_list:
				if path.startswith('/bus.') and path.split("/")[-2] not in self.bus:
					self.bus.append(path.split("/")[-2])

					bus_sensors = self.dir(socknum,path)	
					for sensor in bus_sensors:
						sensor = sensor[7:][:-1] # ID without /
						if sensor[:2].isdigit() and not self.global_sensors.has_key(sensor): #only numeric entrys
							sensor_type = self.read(socknum,sensor + '/' + 'type')
							self.global_sensors.update({sensor:sensor_type})
						
			### First Refresh ###
			self.start = float(time.time())
			self.refresh(socknum)
			duration = float(time.time()) - self.start
			print "Dauer: " + str(duration) + " Sekunden"
			#print "Durchschnitt: " + str(duration/len(self.global_sensors)) + " Sekunden pro Sensor"
			print "Anzahl der Sensoren: " + str(len(self.global_sensors))
			print "Minimum Cycle 1.5 x Lesezeit: " + str(int(1.5*duration)) + " Sekunden."
			
			#self.cycle = 1.5*duration
			self.discovered = True
			
		################################
		#### ENDE OWSERVER ROUTINEN ####
		################################

		### SystemLog (NilsS)
		def log(self,msg,severity='info'):
			#debug,notice,info,warn,error,alert,emerg
			if self.debug:
				logmsg = msg
				## Logausgang
				self.sendout(1,logmsg)
			else: #9
				pass
			## Systemlog-XML
			facility="OneWire"
			xml_logmsg = "<log><id>"+__import__('md5').new(self.__myLogID + str(__import__('time').time())).hexdigest() +"</id><facility>"+facility+"</facility><severity>%s</severity><message>%s</message></log>" % (severity,msg)
			self.sendout(5,xml_logmsg)
			
		### Configuration von String lesen (NilsS)
		def setConfig(self,newconfig):
			if not newconfig:
				return
			for option in newconfig.split('*'):
				try:
					key , val = option.split("=",1)
					## Wert in Integer wandeln
					if type(self._config[key])==int:
						val=int(val)
					## Wenn gültig dann setzen sonst KeyError 
					self._config[key] = val
				except KeyError:
					pass
					###DEBUG###
					#print "Konfig fehlgeschlagen: "+option
				except ValueError:
					pass
					###DEBUG###
					#print "Konfig wrong Value: "+option
			###DEBUG###
			print "Konfig: "+repr(self._config)
		
		### von iko lesen (NilsS)
		def get_ikos(self):
			import re
			_regex = re.compile("owfs.([0-9a-fA-F]+)") ## (i)ko muss im Text owfs.IDIDIDIDIDID haben ## könnte man noch spezieller auf die Länge zuschneiden
			for _iko in self.MC.TagList.TagList.values():
				#_match = _regex.search(_iko.RPCText)
				#if _match:
				#self.onewire_ikos[_match(1)] = _iko ## wenn es ein iko gibt die 1wire ID als key und das iko als value ins Dict schreiben
				#	print "MATCH:"
				print _iko    		### ->  <hs_eib.CTagItem instance at 0x8ed190ec>
				print _iko.RPCText  ### ->  bleibt leer
				print _iko.Value
				print dir(_iko)
				for attr in dir(_iko):
					print "_iko.%s = %s" % (attr, getattr(_iko, attr))
					self.sleep(0.5)
				self.sleep(0.5)
			self.sleep(10)	
		
		## Senden auf die Ausgänge aus dem Thread heraus
		def sendout(self,out,wert):
			## Der Index der Ausgänge fängt bei 0 und nicht bei 1 an
			out -= 1
			###DEBUG###
			#print "Write "+repr(wert)+" (" +str(type(wert))+ ") auf Ausgang "+str(out+1)
			## Auf iKO's schreiben
			try:
				for iko in self.logik.Ausgang[out][1]:
					try:
						iko.setWert(out,wert)
						iko.checkLogik(out)
					except:
						###DEBUG###
						#print "Error writing to iko: "+str(wert)+" (" +str(type(wert))+ ")"
						pass
	
				## Logiken ausführen
				for logik in self.logik.Ausgang[out][3]:
					try:
						logik[0].LogikItem.calc(logik[0],logik[1],wert,0,__import__('time').time())
					except:
						###DEBUG###
						#print "Error writing Outputs: "+str(wert)
						pass
			except AttributeError:
				pass
			
"""])

#code.append([0,"EI","""
### irgendeine Klasse
#if EI==1:
#	class irgendeineKlasse:
#		## Initialisireungsfunktion wird beim erstellen aufgerufen
#		## kann benutzt werden um Variablen zu definieren
#		def init(self,wertvonenirgendwas):
#			self.wert="irgendwas"
#
## Jeder Funktion einer Klasse muss IMMER als erster Parameter self übergeben werden
#		def machwas(self,yippeee):
#			self.wert=yippeee
#			return self.wert
#
#"""])


## Weitere Logikzeilen im hsl FOrmat
postlogik=[0,"","""

## 10Sek Verzögerung zum einlesen der Updateliste - Timer OC[1]
5012|0|"EI"|"1"|"10"|0|1|0|0
5012|0|"EI"|"1"|"20"|0|2|0|0

## Klasse auf SN1
5012|1|"EI"|"knxuf_hsonewire_connector(locals(),EN[1],EN[2])"|""|0|0|1|0

### Wenn Timer dann lasse iButton / IO-Thread starten
5012|0|"OC[1]"|"SN[1]._ibutton_thread()"|""|0|0|0|0
5012|0|"OC[2]"|"SN[1]._io_thread()"|""|0|0|0|0

### Wenn EN[3] dann senden
#5012|0|"EC[3]"|"SN[1].parsecmd(EN[3])"|""|0|0|0|0

"""]


####################################################################################################################################################

###################################################
############## Interne Funktionen #################
###################################################

LGVersion="1.9"

livehost=""
liveport=0
doSend=False
noexec=False
nosource=False
doZip=False
for option in sys.argv:
	if option.find("--new")==0:
		try:
			LOGIKID=int(option.split("=")[1].split(":")[0])
			LOGIKNAME=option.split("=")[1].split(":")[1]
			try: 
				LOGIKCAT=option.split("=")[1].split(":")[2]
			except:
				pass
		except:
			print "--new=id:name[:cat]"
			raise
			sys.exit(1)

		if LOGIKID >99999 or LOGIKID == 0:
			print "invalid Logik-ID"
			sys.exit(1)

		if LOGIKID <10000:
			LOGIKID+=10000
		LOGIKID="%05d" % LOGIKID
		f=open(inspect.currentframe().f_code.co_filename,'r')
		data=""
		while True: 
			line = f.readline()
			if line.find("LOGIKID=") == 0:
				line = "LOGIKID=\""+LOGIKID+"\"\n"
			if line.find("LOGIKNAME=") == 0:
				line = "LOGIKNAME=\""+LOGIKNAME+"\"\n"
			if line.find("LOGIKCAT=") == 0:
				line = "LOGIKCAT=\""+LOGIKCAT+"\"\n"
			data += line
			if not line: 
				break 
		f.close()
		open(str(LOGIKID)+"_"+LOGIKNAME+".py",'w').write(data)
		sys.exit(0)

	if option=="--list":
		showList=True
	  
	if option=="--debug":
		debug=True

	if option=="--noexec":
		noexec=True

	if option=="--nosource":
		nosource=True	

	if option=="--zip":
		doZip=True

	if option=="--nocache":
		doCache=False
	  
	if option.find("--live")==0:
		livedebug=True
		debug=True
		doByteCode=False
		doCache=True
		try:
			livehost=option.split("=")[1].split(":")[0]
			liveport=int(option.split("=")[1].split(":")[1])
		except:
			print "--live=host:port"

	if option.find("--send")==0:
		doSend=True
		try:
			livehost=option.split("=")[1].split(":")[0]
			liveport=int(option.split("=")[1].split(":")[1])
		except:
			print "--send=host:port"
		  

print "HOST: "+livehost+" Port:" +str(liveport)
### DEBUG ####
EI=True
EA=[]
EC=[]
EN=[]
SA=[]
SC=[]
SN=[]
AA=[]
AC=[]
AN=[]
OC=[]
ON=[]
if debug or doSend:
	EA.append(0)
	EC.append(False)
	EN.append(0)
	AA.append(0)
	AC.append(False)
	AN.append(0)
	SA.append(0)
	SC.append(False)
	SN.append(0)
	ON.append(0)
	OC.append(False)

	## Initialisieren ##
	for logikLine in LOGIK.split("\n"):
		if logikLine.find("5001") == 0:
			for i in (range(0,int(logikLine.split("|")[3]))):
			  ON.append(0)
			  OC.append(False)
		if logikLine.find("5002") == 0:
			EN.append(logikLine.split("|")[2])
			EA.append(logikLine.split("|")[2])
			EC.append(False)
		if logikLine.find("5003") == 0:
			if logikLine.split("|")[3][0] == "1":
				SN.append(re.sub('"','',logikLine.split("|")[2]))
			else:
				try:
					SN.append(int(logikLine.split("|")[2]))
				except:
					pass
					SN.append(logikLine.split("|")[2])
			SA.append(logikLine.split("|")[2])
			SC.append(False)
		if logikLine.find("5004") == 0:
			AN.append(logikLine.split("|")[2])
			AA.append(logikLine.split("|")[2])
			AC.append(False)


def bool2Name(b):
  if int(b)==1:
	return "Ja"
  else:
	return "Nein"
def sbc2Name(b):
  if int(b)==1:
	return "Send"
  else:
	return "Send By Change"


def addInputDoku(num,init,desc):
  return '<tr><td class="log_e1">Eingang '+str(num)+'</td><td class="log_e2">'+str(init)+'</td><td class="log_e3">'+str(desc)+'</td></tr>\n'
def addOutputDoku(num,sbc,init,desc):
  return '<tr><td class="log_a1">Ausgang '+str(num)+' ('+sbc2Name(sbc)+')</td><td class="log_a2">'+str(init)+'</td><td class="log_a3">'+str(desc)+'</td></tr>\n'

LOGIKINHTM=""
LOGIKOUTHTM=""

i=0
LEXPDEFINELINE=LHSDEFINELINE=LINDEFINELINE=LSPDEFINELINE=LOUTDEFINELINE=0
for logikLine in LOGIK.split("\n"):
	if logikLine.find("5000") == 0:
		LEXPDEFINELINE=i
		LOGIKREMANT=bool2Name(logikLine.split("|")[2])
		LOGIKDEF=logikLine
	if logikLine.find("5001") == 0:
		LHSDEFINELINE=i
		ANZIN=int(logikLine.split("|")[1])
		ANZOUT=int(logikLine.split("|")[2])
		ANZSP=int(logikLine.split("|")[4])
		CALCSTARTBOOL=logikLine.split("|")[5]
		CALCSTART=bool2Name(CALCSTARTBOOL)
	if logikLine.find("5002") == 0:
		LINDEFINELINE=i
		desc=re.sub('"','',LOGIKDEF.split("|")[3+int(logikLine.split("|")[1])])
		if logikLine.find("#*") >0:
			desc=logikLine.split("#*")[1]
		LOGIKINHTM+=addInputDoku(logikLine.split("|")[1],logikLine.split("|")[2],desc)
	if logikLine.find("5003") == 0 or logikLine.find("# Speicher") == 0:
		LSPDEFINELINE=i
	if logikLine.find("5004") == 0:
		LOUTDEFINELINE=i
		desc=re.sub('"','',LOGIKDEF.split("|")[(4+ANZIN+int(logikLine.split("|")[1]))])
		if logikLine.find("#*") >0:
			desc=logikLine.split("#*")[1]
		LOGIKOUTHTM+=addOutputDoku(logikLine.split("|")[1],logikLine.split("|")[4],logikLine.split("|")[2],desc)
	i=i+1


if livedebug:
	EC.append(0)
	EN.append("")


sendVars=""

for option in sys.argv:
	if option.find("--sa") == 0:
		SA[int(option[4:option.find("=")])]=option.split("=")[1]
		sendVars+="SA["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
	if option.find("--sn") == 0:
		SN[int(option[4:option.find("=")])]=option.split("=")[1]
		SC[int(option[4:option.find("=")])]=True
		sendVars+="SN["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
		sendVars+="SC["+str(int(option[4:option.find("=")]))+"]=1\n"
	if option.find("--aa") == 0:
		AA[int(option[4:option.find("=")])]=option.split("=")[1]
		sendVars+="AA["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
	if option.find("--an") == 0:
		AN[int(option[4:option.find("=")])]=option.split("=")[1]
		AC[int(option[4:option.find("=")])]=True
		sendVars+="AN["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1:]+"\n"
		sendVars+="AC["+str(int(option[4:option.find("=")]))+"]=1\n"
	if option.find("--ea") == 0:
		EA[int(option[4:option.find("=")])]=option.split("=")[1]
		sendVars+="EA["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1:]+"\n"
	if option.find("--en") == 0:
		EN[int(option[4:option.find("=")])]="".join(option.split("=",1)[1])
		EC[int(option[4:option.find("=")])]=True
		sendVars+="EN["+str(int(option[4:option.find("=")]))+"]="+"".join(option.split("=")[1:])+"\n"
		sendVars+="EC["+str(int(option[4:option.find("=")]))+"]=1\n"
	if option.find("--ec") == 0:
#		EC[int(option[4:option.find("=")])]=int(option.split("=")[1])
		sendVars+="EC["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
		print sendVars
	if option.find("--sc") == 0:
#		EC[int(option[4:option.find("=")])]=int(option.split("=")[1])
		sendVars+="SC["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
		print sendVars
	if option.find("--on") == 0:
		ON[int(option[4:option.find("=")])]=option.split("=")[1]
		sendVars+="ON["+str(int(option[4:option.find("=")]))+"]="+option.split("=")[1]+"\n"
	if option.find("--oc") == 0:
		OC[int(option[4:option.find("=")])]=True
		sendVars+="OC["+str(int(option[4:option.find("=")]))+"]=1\n"
	if option.find("--ei") == 0:
		EI=(int(option.split("=")[1])==1)
		sendVars+="EI=1\n"
	if option.find("--run") == 0:
		sendVars+="eval(SN["+str(ANZSP+1)+"])\n"


def symbolize(LOGIK,code):
	  symbols = {}
	  for i in re.findall(r"(?m)^500([234])[|]([0-9]{1,}).*[@][@](.*)\s", LOGIK):
		  varName=((i[0]=='2') and 'E') or ((i[0]=='3') and 'S') or ((i[0]=='4') and 'A')
		  isunique=True
		  try:
			  type(symbols[i[2]])
			  sym=i[2]
			  isunique=False
		  except KeyError:
			  pass
		  ## überprüft auch die alternativen Varianten
		  if re.match("[ACN]",i[2][-1:]):
			  try:
				  type(symbols[i[2][:-1]])
				  sym=i[2][:-1]
				  isunique=False
			  except KeyError:
				  pass
		  if isunique:
			  symbols[i[2]]=[varName,"["+i[1]+"]"]
		  else:
			  print "Variablen Kollision :" +repr(i[2])+" ist in " +repr(symbols[sym]) + " und  "+ varName +"["+i[1]+"] vergeben"
			  sys.exit(1)

	  ## Symbole wieder entfernen
	  LOGIK=re.sub("[@][@]\w+", "",LOGIK)

	  #im Code tauschen
	  for i in symbols.keys():
		  code=[code[0],re.sub("[\@][\@]"+i+"([ACN])",symbols[i][0]+"\\1"+symbols[i][1],code[1]),re.sub("[\@][\@]"+i+"([ACN])",symbols[i][0]+"\\1"+symbols[i][1],code[2])]
		  code=[code[0],re.sub("[\@][\@]"+i+"",symbols[i][0]+"N"+symbols[i][1],code[1]),re.sub("[\@][\@]"+i+"",symbols[i][0]+"N"+symbols[i][1],code[2])]
	  return LOGIK,code

NCODE=[]
commentcode=[]
for codepart in code:
	NLOGIK,codepart=symbolize(LOGIK,codepart)

	NCODE.append(codepart)

	if codepart[0]==0 or codepart[0]==3:
		commentcode.append("##########################\n###### Quelltext: ########\n##########################"+"\n##".join(codepart[2].split("\n"))+"\n")
	else:
		commentcode.append("#"+codepart[2].split("\n")[1]+"\n################################\n## Quelltext nicht Öffentlich ##\n################################")


NLOGIK,postlogik = symbolize(LOGIK,postlogik)
LOGIK=NLOGIK

code=NCODE

## Doku
doku = """
<html>
<head><title></title></head>
<link rel="stylesheet" href="style.css" type="text/css">
<body><div class="titel">"""+LOGIKNAME+"""</div>
<div class="nav"><A HREF="index.html">Hilfe</A> / <A HREF="logic.html">Logik</A> / """+LOGIKNAME+""" / <A HREF="#anker1">Eing&auml;nge</A> / <A HREF="#anker2">Ausg&auml;nge</A></div><div class="field0">Funktion</div>
<div class="field1">"""+re.sub("\n","<br>",LOGIKDESC)+"""</div>
<div class="field0">Eingänge</div>
<a name="anker1" /><table border="1" width="612" class="log_e" cellpadding="0" cellspacing="0">
<COL WIDTH=203><COL WIDTH=132><COL WIDTH=275>
<tr><td>Eingang</td><td>Init</td><td>Beschreibung</td></tr>
"""+LOGIKINHTM+"""
</table>
<div class="field0">Ausgänge</div>
<a name="anker2" /><table border="1" width="612" class="log_a" cellpadding="0" cellspacing="0">
<COL WIDTH=203><COL WIDTH=132><COL WIDTH=275>
<tr><td>Ausgang</td><td>Init</td><td>Beschreibung</td></tr>
"""+LOGIKOUTHTM+"""
</table>
<div class="field0">Sonstiges</div>
<div class="field1">Neuberechnung beim Start: """+CALCSTART+"""<br />Baustein ist remanent: """+LOGIKREMANT+"""<br />Interne Bezeichnung: """+LOGIKID+"""<br />Der Baustein wird im "Experten" in der Kategorie '"""+LOGIKCAT+"""' einsortiert.<br /></div>
</body></html>
"""

if doDoku:
  open("log"+LOGIKID+".html",'w').write(doku)


LIVECODE="""
if EN["""+str(ANZIN+1)+"""].find("<id"""+LOGIKID+""">")!=-1:
	print "LivePort " +str(len(EN["""+str(ANZIN+1)+"""]))+ " Bytes erhalten"
	try:
		__LiveDebugCode_="".join(__import__('re').findall("(?i)<id"""+LOGIKID+""">(.*)</id"""+LOGIKID+""">",EN["""+str(ANZIN+1)+"""]))
		print "LiveDebug-Daten ID:"""+LOGIKID+" Name:"+LOGIKNAME+""" "
	except:
		pass
		print "Fehler Datenlesen"
		__LiveDebugCode_=''
	if __LiveDebugCode_.find("<inject>") != -1:
		SN["""+str(ANZSP+2)+"""]+="".join(__import__('re').findall("(?i)<inject>([A-Za-z0-9\\x2B\\x3D\\x2F]+?)</inject>", __LiveDebugCode_))
		print "Daten erhalten Buffer: " + str(len(SN["""+str(ANZSP+2)+"""]))
	elif  __LiveDebugCode_.find("<compile />") != -1:
		print "Compile"
		try:
			__LiveBase64Code_=__import__('base64').decodestring(SN["""+str(ANZSP+2)+"""])
			print __LiveBase64Code_
		except:
			pass
			print "Base64 Error"
			raise
		try:
			SN["""+str(ANZSP+1)+"""]=compile(__LiveBase64Code_,'<LiveDebug_"""+LOGIKID+""">','exec')
			SC["""+str(ANZSP+1)+"""]=1
			print "Running"
		except:
			__import__('traceback').print_exc(file=__import__('sys').stdout)
			pass
			SN["""+str(ANZSP+1)+"""]="0"
			SC["""+str(ANZSP+1)+"""]=1
			print "Compile Error"

		SN["""+str(ANZSP+2)+"""]=''
	elif __LiveDebugCode_.find("<vars>") == 0:
		print "Run Script"
		try:
			__LiveBase64Code_=__import__('base64').decodestring("".join(__import__('re').findall("(?i)<vars>([A-Za-z0-9\\x2B\\x3D\\x2F]+?)</vars>", __LiveDebugCode_)))
		except:
			pass
			print "Script Base64 Error"
			__LiveBase64Code_='0'
		try:
			eval(compile(__LiveBase64Code_,'<LiveDebugVars"""+LOGIKID+""">','exec'))
		except:
			__import__('traceback').print_exc(file=__import__('sys').stdout)
			pass
			print "Script Error" 
			print __LiveBase64Code_
			#print  __import__('traceback').print_exception(__import__('sys').exc_info()[0],__import__('sys').exc_info()[1],__import__('sys').exc_info()[2])
			raise
	else:
		print "unbekanntes TAG: " + repr(__LiveDebugCode_)
"""




#print LIVECODE

LOGIKFILE=LOGIKID+"_"+LOGIKNAME

## Debug Lines
NCODE=[]
if debug or livedebug:
	for codepart in code:
		codepart[2]=re.sub("###DEBUG###","",codepart[2])
		NCODE.append(codepart)
	code=NCODE

#print "\n".join(code)
def commentRemover(code):
	## Komentar Remover 
	## thanks to gaston
	codelist=code[2].split("\n")
	removelist=[]
	lencode=len(codelist)-1
	for i in range(1,lencode):
		codeline=codelist[lencode-i].lstrip(" \t")
		if len(codeline)>0:
			if codeline[0]=='#':
				removelist.insert(0,"REMOVED: ("+str(lencode-i)+") "+codelist.pop(lencode-i))
		else:
			codelist.pop(lencode-i)
	return ([code[0],code[1],"\n".join(codelist)],"\n".join(removelist))

Nremoved=""
NCode=[]
for codepart in code:
	codepart, removed=commentRemover(codepart)
	Nremoved=Nremoved+removed
	NCode.append(codepart)

code=NCode

print Nremoved
print "\n\n"


#print code

if livedebug:
	NCODE="\n##### VERSION #### %04d-%02d-%02d %02d:%02d:%02d ###\n" % time.localtime()[:6]
	code.append(NCODE)

CODELENGTH=len(repr(code))



breakStart=str((int(CALCSTARTBOOL)-1)*-1)
LOGIKARRAY=LOGIK.split("\n")
lformel=""
def compileMe(code,doByteCode,BEDINGUNG=''):
	if doByteCode:
		data=compile(code,"<"+LOGIKFILE+">","exec")
		data=marshal.dumps(data)
		if sys.version[:3]=="2.2":
			## Insecure MKTEMP for 2.4 Compile
			codefile=tempfile.mktemp()
			f=open(codefile,"w")
			f.write(base64.encodestring(code))
			f.close()
			codetwofour=""
			try:
				stdout,stdin,stderr = popen2.popen3(r"C:\python24\python24.exe compile24.py "+codefile+" "+LOGIKFILE)
				codetwofour=base64.decodestring(stdout.read())
				stdout.close()
				stdin.close()
				print stderr.readlines()
				stderr.close()
				data=(data,codetwofour)
			except:
				pass
				print "NO 2.4 Compile"
			os.unlink(codefile)
		version=sys.version[:3]
		formel=""
		for data in data:
			if doByteCode==2:
				formel += "5012|0|\"("+BEDINGUNG+") and (__import__('sys').version[:3]=='"+version+"')\"|\"eval(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').decodestring('"+re.sub("\n","",base64.encodestring(zlib.compress(data,6)))+"'))))\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
			else:
				formel += "5012|0|\"("+BEDINGUNG+") and (__import__('sys').version[:3]=='"+version+"')\"|\"eval(__import__('marshal').loads(__import__('base64').decodestring('"+re.sub("\n","",base64.encodestring(data))+"')))\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
			version="2.4"
			formel+="\n"

	else:
		if doCache:
			LOGIKDEFARRAY=LOGIKARRAY[LHSDEFINELINE].split("|")
			if livedebug:
				LOGIKDEFARRAY[4]=str(ANZSP+2)
			else:
				LOGIKDEFARRAY[4]=str(ANZSP+1)
			LOGIKARRAY[LHSDEFINELINE]="|".join(LOGIKDEFARRAY)
			LOGIKARRAY[LSPDEFINELINE]+="\n"+"5003|"+str(ANZSP+1)+"|\"0\"|0 # Base64 Code-Cache"
			if livedebug:
				LOGIKARRAY[LSPDEFINELINE]+="\n"+"5003|"+str(ANZSP+2)+"|\"\"|0 # LivePortBase64Buffer"
			if livedebug:
				formel = "5012|0|\"EI or EC["+str(ANZIN+1)+"]\"|\"eval(compile(__import__('base64').decodestring('"+re.sub("\n","",base64.encodestring(LIVECODE))+"'),'<"+LOGIKFILE+">','exec'))\"|\"\"|0|0|0|0\n"
				#formel += "5012|0|\"("+BEDINGUNG+") or SC["+str(ANZSP+1)+"]\"|\"eval(SN["+str(ANZSP+1)+"])\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
				formel += "5012|0|\"\"|\"eval(SN["+str(ANZSP+1)+"])\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
			else:
				formel = "5012|0|\"EI\"|\"compile(__import__('base64').decodestring('"+re.sub("\n","",base64.encodestring(code))+"'),'<"+LOGIKFILE+">','exec')\"|\"\"|0|0|"+str(ANZSP+1)+"|0\n"
				formel += "5012|0|\""+BEDINGUNG+"\"|\"eval(SN["+str(ANZSP+1)+"])\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
		else:
			formel = "5012|0|\""+BEDINGUNG+"\"|\"eval(compile(__import__('base64').decodestring('"+re.sub("\n","",base64.encodestring(code))+"'),'<"+LOGIKFILE+">','exec'))\"|\""+ZEITFORMEL+"\"|0|"+ZEITSPEICHER+"|0|0"
	formel+="\n## MD5 der Formelzeile: "+md5.new(formel).hexdigest()
	return formel+"\n"

formel=""
for i in range(len(code)):
	codepart=code[i]
	if codepart[0]==1:
		tempBC=1
	if codepart[0]==2:
		tempBC=2
	else:
		tempBC=doByteCode
	if livedebug:
		doCache=True
		formel=compileMe(LIVECODE,False,BEDINGUNG="")
		break
	formel+=compileMe(codepart[2],tempBC,BEDINGUNG=codepart[1])
	formel+=commentcode[i]+"\n\n"
		
### DEBUG ###

formel+="\n"+postlogik[2]

## Debuggerbaustein

if livedebug:
	LOGIKDEFARRAY=LOGIKARRAY[LEXPDEFINELINE].split("|")
	LOGIKDEFARRAY[3]=str(ANZIN+1)
	LOGIKDEFARRAY[3+ANZIN]+="|\"E"+str(ANZIN+1)+" DEBUG\""
	LOGIKARRAY[LEXPDEFINELINE]="|".join(LOGIKDEFARRAY)
	LOGIKDEFARRAY=LOGIKARRAY[LHSDEFINELINE].split("|")
	LOGIKDEFARRAY[1]=str(ANZIN+1)
	LOGIKARRAY[LHSDEFINELINE]="|".join(LOGIKDEFARRAY)
	LOGIKARRAY[LINDEFINELINE]+="\n"+"5002|"+str(ANZIN+1)+"|\"\"|1 # Debugger Live in"


LOGIK = "\n".join(LOGIKARRAY)

allcode=""
for i in code:
  allcode+=i[2]+"\n"

if showList:
	codeobj=allcode.split("\n")
	for i in range(0,len(codeobj)):
		print str(i)+": "+codeobj[i]

if debug and not livedebug:
	debugstart=time.clock()
	if not noexec:
		exec(allcode)
	else:
		compile(allcode,"<code>","exec")

	debugtime=time.clock()-debugstart
	print "Logikausfuehrzeit: %.4f ms" % (debugtime)
	if debugtime>1:
	  print """
###############################################
### !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ###
### !!!ACHTUNG: sehr lange Ausfürungszeit!! ###
### !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ###
###############################################
"""

if debug or doSend:
	del EN[0]
	del SN[0]
	del AN[0]

if livedebug:
	#formel=lformel
	LOGIK="""############################\n####  DEBUG BAUSTEIN #######\n############################\n"""+LOGIK
	livesend=re.sub("\n","",base64.encodestring(allcode))
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.connect((livehost,liveport))
	Livepackets=0
	while livesend!="":
		Livepackets+=1
		sock.sendall("<xml><id"+LOGIKID+"><inject>"+livesend[:4000]+"</inject></id"+LOGIKID+"></xml>")
		livesend=livesend[4000:]
		time.sleep(0.1)
	time.sleep(1)
	sock.sendall("<xml><id"+LOGIKID+"><compile /></id"+LOGIKID+"></xml>")
	print str(Livepackets)+ " Packet per UDP verschickt"
	sock.close()

if doSend:
	## Das auslösen über den Debug verhindern
	sendVars="EC["+str(ANZIN+1)+"]=0\n"+sendVars
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.connect((livehost,liveport))
	sock.sendall("<xml><id"+LOGIKID+"><vars>"+re.sub("\n","",base64.encodestring(sendVars)+"</vars></id"+LOGIKID+"></xml>\n"))
	sock.close()


if VERSION !="":
	VERSION="_"+VERSION
if debug:
	VERSION+="_DEBUG"


open(LOGIKFILE+VERSION+".hsl",'w').write(LOGIK+"\n"+formel+"\n")
def md5sum(fn):
	m = md5.new()
	f=open(fn,'rb')
	while True: 
		data = f.read(1024) 
		if not data: 
			break 
		m.update(data) 
	f.close()
	return m.hexdigest() + " *" + fn + "\n"
	
chksums = md5sum(LOGIKFILE+VERSION+".hsl")
if not nosource:
	chksums += md5sum(inspect.currentframe().f_code.co_filename)
if doDoku:
	chksums += md5sum("log"+LOGIKID+".html")

open(LOGIKFILE+".md5",'w').write(chksums)

if doZip:
	#os.remove(LOGIKFILE+VERSION+".zip")
	z=zipfile.ZipFile(LOGIKFILE+VERSION+".zip" ,"w",zipfile.ZIP_DEFLATED)
	if not nosource:
		z.write(inspect.currentframe().f_code.co_filename)
	if doDoku:
		z.write("log"+LOGIKID+".html")
	z.write(LOGIKFILE+VERSION+".hsl")
	z.write(LOGIKFILE+".md5")
	z.close()

print "Baustein \"" + LOGIKFILE + "\" erstellt"
print "Groesse:" +str(CODELENGTH)

if livedebug:
	print "########################################"
	print "####	   DEBUGBAUSTEIN			####"
	print "########################################"

print """
Neuberechnung beim Start: """+CALCSTART+"""
Baustein ist remanent: """+LOGIKREMANT+"""
Interne Bezeichnung: """+LOGIKID+"""
Kategorie: '"""+LOGIKCAT+"""'
Anzahl Eingänge: """+str(ANZIN)+"""   """+repr(EN)+"""
Anzahl Ausgänge: """+str(ANZOUT)+"""  """+repr(AN)+"""
Interne Speicher: """+str(ANZSP)+"""  """+repr(SN)+"""
"""
