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

	def __init__(self, prs):
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

	def injector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			try:
				bssid = pkt.getlayer(Dot11FCS).addr2
			except:
				bssid = pkt.getlayer(Dot11).addr2

			essid = self.extract_essid(pkt.getlayer(Dot11Elt))
			channel = self.extractc_channel(pkt.getlyer(Dot11Elt))

			toappend = {
				'essid': essid,
				'bssid': bssid,
				'channel': channel
			}

	def engage(self):
		sniff(iface=self.interface, prn=self.injector)

class PARSER:

	def __init__(self, opts):
		self.world       = opts.world
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
		self.reset       = opts.reset   if ((opts.reset == 0) or (opts >= 5)) else pull.halt("Reset Must Be >= 5. ")
		self.code        = opts.code    if ((opts.code >= 1) and (opts.code <= 66)) else pull.halt("Code Must Be Greater Greater >= 1 and <= 66")

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
					retval.append(bssid)

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
	parser = argparse.ArgumentParser(add_help=True)

	parser.add_argument('-i', '--interface'   , dest="interface", default="", type=str)

	parser.add_argument('-c', '--channel'     , dest="channel"  , default=0 , type=int)
	parser.add_argument('-a', '--accesspoints', dest="aps"   , default="", type=str)
	parser.add_argument('-s', '--stations'    , dest="stations", default="", type=str)
	parser.add_argument('-f', '--filters'     , dest="filters" , default="", type=str)

	parser.add_argument('-p', '--packets'     , dest="packets" , default=1 , type=int)
	parser.add_argument('-d', '--delay'       , dest="delay"   , default=0.1, type=int)
	parser.add_argument('-r', '--reset'       , dest="reset"   , default=0  , type=int)
	parser.add_argument('--code'              , dest="code"    , default=7  , type=int)

	parser.add_argument('--world'             , dest="world"     , default=False, action="store_true")
	parser.add_argument('--no-broadcast'      , dest="nbroadcast", default=False, action="store_true")
	parser.add_argument('--verbose'           , dest="verbose"   , default=False, action="store_true")

	options = parser.parse_args()
	parser = PARSER(options)

	pull.print(
		"*",
		"IFACE [{interface}] CHANNEL [{channel}] VERBOSE [{verbose}]".format(
			interface=pull.DARKCYAN+parser.interface+pull.END,
			channel=pull.DARKCYAN+str(("HOP" if len(parser.channel) > 1 else parser.channel[0]))+pull.END,
			verbose=pull.DARKCYAN+("True" if parser.verbose else "False")
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

if __name__ == "__main__":
	pull = PULL()
	main()