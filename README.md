# WiFiJammer.py

Continuously Jams all the Devices In the Area. Start. It will continue on scanning the nearby Wireless networks and sending Deauthentication Packets.

## Usage:
```
python [scriptname] [argument...]
python wifijammer.py --all
```

### Arguments
```
-a, --ap=	BSSID of Target AP
-c, --client=	BSSID of Client (Requires Access Point Mac Address)
-h, --help	This Help Manual
-o, --out=	comma-seperated BSSID's which you don't want to send Deauth Packets
-a, --all	Sent Deauth Packets to all nearby Devices.
```

## Examples:

Send Deauth packets to all nearby WiFi Networks. Even Hidden Networks.
```
python wifijammer.py --all
```
Send Deauth packets to only a specific Target Acess Point

```
python wifijammer.py -a FF:FF:FF:FF:FF:FF
```

Send Deauth packets to a specific client of a specific Access Point
```
python wifijammer.py -a FF:FF:FF:FF:FF:FF -c FF:FF:FF:FF:FF:FF
```
Send Deauth packets to all nearby devices other than FF:FF:FF:FF:FF:FF and BB:BB:BB:BB:BB:BB
```
python wifijammer.py --all --out=FF:FF:FF:FF:FF:FF,BB:BB:BB:BB:BB:BB:BB
```

### Credits
Twitter: <a href="//twitter.com/hash3liZer">hash3liZer</a><br>
Email  : <a href="mailto:admin@shellvoide.com">admin@shellvoide.com</a>
