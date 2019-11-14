import os
import sys
import random


__help__ = """Usage:
wifijammer.py [--argument] [value]

Args                 Description                       Default
-h, --help           Throwback this help manaul        False
-i, --interface      Monitor Mode Interface to use
                     for scanning & deauthentication   None
-c, --channel        Channel to put monitor interface
                     on                                All
-a, --accesspoints   Comma-seperated list of access-
                     points to target                  All
-s, --stations       Comma-seperated list of stations
                     to target                         All
-f, --filters        Comma-seperated list of Mac-
                     addresses to skip target          None
-p, --packets        Number of deauthentication
                     packets to send per turn.         5
-d, --delay          Delay b/w transmission of pkts    0.1s
-r, --reset          To refresh the target list after 
                     the list has reached a specific
                     number, like --reset 5            None
    --code           (Int) Deauthentication Code
                     to send with packets               7
    --world          Scan for channels from 1-14,
                     default is 1-11                   False
    --aggressive     Run in Aggressive Mode. Send 
                     Continuous frames to Broadcast
                     Doesn't work when hoppping.        False
    --no-broadcast   Don't send deauthentication 
                     packets to broadcast address      False
    --verbose        Print device manufacturing
                     details                           False
"""

class PULL:

	WHITE = '\033[0m'
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
	LINEUP = '\033[F'

	MIXTURE = {
		'WHITE': '\033[0m',
		'PURPLE': '\033[95m',
		'CYAN': '\033[96m',
		'DARKCYAN': '\033[36m',
		'BLUE': '\033[94m',
		'GREEN': '\033[92m',
		'YELLOW': '\033[93m',
		'RED': '\033[91m',
		'BOLD': '\033[1m',
		'UNDERLINE': '\033[4m',
		'END': '\033[0m',
		'LINEUP': '\033[F'
	}

	VACANT = {
		'WHITE': '',
		'PURPLE': '',
		'CYAN': '',
		'DARKCYAN': '',
		'BLUE': '',
		'GREEN': '',
		'YELLOW': '',
		'RED': '',
		'BOLD': '',
		'UNDERLINE': '',
		'END': '',
		'LINEUP': ''
	}

	def __init__(self):
		if not self.support_colors:
			self.win_colors()

	def support_colors(self):
		plat = sys.platform
		supported_platform = plat != 'Pocket PC' and (plat != 'win32' or \
														'ANSICON' in os.environ)
		is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
		if not supported_platform or not is_a_tty:
			return False
		return True

	def win_colors(self):
		self.WHITE = ''
		self.PURPLE = ''
		self.CYAN = ''
		self.DARKCYAN = ''
		self.BLUE = ''
		self.GREEN = ''
		self.YELLOW = ''
		self.RED = ''
		self.BOLD = ''
		self.UNDERLINE = ''
		self.END = ''
		self.MIXTURE = {
			'WHITE': '',
			'PURPLE': '',
			'CYAN': '',
			'DARKCYAN': '',
			'BLUE': '',
			'GREEN': '',
			'YELLOW': '',
			'RED': '',
			'BOLD': '',
			'UNDERLINE': '',
			'END': '',
			'LINEUP': ''
		}

		for key in list(self.MIXTURE.items()):
			self.MIXTURE[ key ] = ''

	def linebreak(self, howmany=1):
		for n in range(0, howmany):
			sys.stdout.write( "\n" )

	def print(self, sig, statement, *colors):
		cc = ''
		cc = "".join([color for color in colors])
		print("{mix}[{sig}]{end} {statement}".format(
				sig=sig,
				mix=cc,
				end=self.END,
				statement=statement
			))

	def verbose(self, sig, statement, verbose, *colors):
		if verbose:
			cc = ''
			cc = "".join([color for color in colors])
			print("{mix}[{sig}]{end} {statement}".format(
					sig=sig,
					mix=cc,
					end=self.END,
					statement=statement
				))

	def input(self, sig, statement, validation=(), *colors):
		cc = ''
		cc = "".join([color for color in colors])
		value = input("{mix}[{sig}]{end} {statement}".format(
					sig=sig,
					mix=cc,
					end=self.END,
					statement=statement
				))
		if value:
			if validation:
				if validation[0].lower() == value.lower():
					return True
				elif validation[1].lower() == value.lower():
					return False
				else:
					self.print("!", "Something Not Valid here. Enter a Valid Value.", self.RED)
					value = self.input(sig, statement, validation, cc)
			else:
				return value
		else:
			self.print("!", "Something Not Valid here. Enter a Valid Value.", self.RED)
			value = self.input(statement, validation, cc)			

		return value

	def halt(self, statement, exit, *colors):
		cc = ''
		cc = "".join([color for color in colors])
		print("{mix}[~]{end} {statement}".format(
				mix=cc,
				end=self.END,
				statement=statement
			))
		if exit:
			sys.exit(-1)

	def get_mac(self, bss):
		retval = ''

		if os.path.isfile(os.path.join(os.getcwd(), 'maclist', 'macs.txt')):
			lines = open(os.path.join(os.getcwd(), 'maclist', 'macs.txt'))
			for line in lines:
				line = line.split( " ~ " )
				if bss.lower().startswith(line[0].lower()[:8]):
					retval = line[1].split(" ")[0]

		return retval

	def help(self):
		sys.exit(
				__help__
			)

	def logo(self):
		color = random.choice([
				self.DARKCYAN,
				self.RED,
				self.YELLOW,
			])
		print(
			"{mcolor}{bcolor}{body}{ecolor}\n\t\t{amcolor}@hash3liZer v1.0{aecolor}\n".format(
					mcolor=color,
					bcolor=self.BOLD,
					body=__logo__,
					ecolor=self.END,
					amcolor=self.BOLD,
					aecolor=self.END
				)
			)