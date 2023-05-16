# rcPCAPanalyzer
#######################################################################

Red Crow Labs

#######################################################################
DESCRIPTION:

rcPCAPanalyzer is PoC Code to analyze a PCAP file looking for basic anomalies. It performs the following actions:

- Extracts a list of IPs contacted by the given source IP.
- Performs a DNS lookup on each IP from the list.
- Geolocates each IP in the list.
- Count the number of connections between the given source IP and each contacted IP.
- Calculates the total traffic volume between the source IP and each contacted IP.
- Attempts to identify incorrect protocol usage. (Ex. HTTP over port 22)
- Looks for anomalous TTL values between connections.
- Detects DNS tunneling.
- Detects executables (EXE and ELF) in the network stream.
- Detects basic shell commands (ex. cmd.exe, /bin/bash) in the network stream.
- Finds periodicity that might indicate C2 or beacons.


=========================================================================
INSTALL: 

git clone https://github.com/redcrowlab/rcPCAPanalyzer.git



=========================================================================
USAGE: 

python rcPCAPanalyzer [pcap file] [source IP]


=========================================================================
NOTE:

This code is prone to false positives. 
