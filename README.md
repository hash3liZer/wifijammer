# WiFiJammer.py

Name: WiFiJammer.py
Description: Continuously Jams all the Devices In the Area. Start The script and take Your Device whereever you want. It will continue on scanning the nearby Wireless networks and sending Deauthentication Packets. You can also choose to leave some targets, so that they cannot get affected by the script and keep functioning as normal.  

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
