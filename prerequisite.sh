#!/usr/bin/env sh
if command -v pip3 >/dev/null 2>&1; then
    /usr/bin/sudo pip3 install scapy==2.4.3
else
    printf "${NORMAL}Please install pip3."
fi
