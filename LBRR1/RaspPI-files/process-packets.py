#! /usr/bin/python3

import sys, os, time
from pathlib import Path

"""
	process only .pcap files within the specified directory
"""
### Variables
homeDir  = str(Path.home())
pcapDir  = homeDir + '/pcaps/'
duration = 60 #300=5min
parser   = homeDir + '/parse-packets.py'
try :
	parseIP = sys.argv[1]
except :
	parseIP = '10.60.11.11'

### Saves pcaps to file in incremental chunks
"""
command = "tshark -b duration:{0} -i eth0 -w {1}/packet.pcap > /dev/null &".format(duration, directory)
os.system(command)
"""

# Continuously try to process pcaps
while True :
	time.sleep(1)

	### Obtains and sorts the contents of the directory
	listDir = sorted(os.listdir(pcapDir))

	### Creates a list of just the .pcap files
	pcapList = []
	for file in listDir :
		if file.endswith('.pcap') :
			pcapList.append(pcapDir + file)

	### Processes pcaps if there are more than one
	if len(pcapList) > 1 :
		### Removes the latest pcap from being processed, as it still may being written to
		pcapList.pop()

		for pcap in pcapList :
			### Processes the pcap with the other parse packets script
			print('Processing: ' + pcap)
			command = "{0} {1} {2}".format(parser, pcap, parseIP)
			print('Command:    ' + command)
			os.system(command)
			print('Removing:   ' + pcap)
			os.remove(pcap)
			print('')
	else :
		print("[!] There is only one pcap file, it may still may being written to. To process a single file, use the parse-packet.py script.")

