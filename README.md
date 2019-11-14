# wifijammer
Disconnect Nearby Access Points and Stations by forging and Transmitting Deauthentication Frames. Built on top of scapy and utilizes channel hopping and forging frames from a single interface. Works with **python 3**.

## Installation:
Install Scapy: 
```
$ pip3 install scapy==2.4.3
```
Clone the Repo and check manual: 
```
$ git clone https://github.com/hash3liZer/wifijammer.git
$ cd wifijammer/
$ python3 wifijammer.py --help
```

## Usage:
```
python3 [scriptname] [argument...]
python3 wifijammer.py --help
```

### Arguments
```
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
                     packets to send per turn.         25
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
                     Doesn't work when hoppping        False
    --no-broadcast   Don't send deauthentication 
                     packets to broadcast address      False
    --verbose        Print device manufacturing
                     details                           False
```
### Example
Disconnecting AccessPoints from their stations on channel 6:
```
$ python3 wifijammer.py --interface wlan1mon --channel 6 --aggressive
```

### Disclaimer
This tool is only intended for testing purposes and should be used where there is allowance of having de-authentication tests. The user should have prior consent for testing against the target. The author will not be held responsible regarding any case of misuse. 

### Author
Twitter: <a href="//twitter.com/hash3liZer">hash3liZer</a><br>
Email  : <a href="mailto:admin@shellvoide.com">admin@shellvoide.com</a>
