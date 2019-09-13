# wifijammer

A wireless jammer that send deauthentication frames to dissociate access point and station. Built on scapy and works with Python 3. The jamming will heavily depend on your what kind of wireless adapter you are using. 

## Installation:
Install Scapy: 
```
$ pip install scapy==2.4.3
```
Clone the Repo and check manual: 
```
$ git clone https://github.com/hash3liZer/wifijammer.git
$ cd wifijammer/
$ python wifijammer.py --help
```

## Usage:
```
python [scriptname] [argument...]
python wifijammer.py --help
```

### Arguments
```
Args                  Description                       Default
 -h, --help           Throwback this help manaul        False
 -i, --interface      Monitor Mode Interface to use.    None  
 -c, --channel        Channel on which to send          Hopping
                      deauthentication frames
 -e, --essids         Essids to Jam                     None
 -a, --access-points  Mac of Access Points to Jam       None
 -s, --stations       Mac of Stations to Jam            None
 -f, --filters        List of Mac addresses to not Jam. None
     --verbose        Print Verbose Messages.           False

```

### Author
Twitter: <a href="//twitter.com/hash3liZer">hash3liZer</a><br>
Email  : <a href="mailto:admin@shellvoide.com">admin@shellvoide.com</a>
