#! /usr/bin/python3

from scapy.all import *
import sys,csv,time

"""
usage:
    Syntax
    ./get-network-statistics.py <network_interface> <destination_path>
"""

#The directory that PLI data will be saved to
if sys.argv[2]:
    savePath = sys.argv[2] 
else:
    savePath = '/home/coeus/Desktop/PC22/packet-capture/network-statistics'
command = f"mkdir -p {savePath} 2> /dev/null"
os.system(command)


savefile  = f"{savePath}/net-stats.csv"
#{datetime.datetime.now()}
if os.path.isfile(savefile):
    pass
else:
    with open(savefile, 'w', newline='') as csvfile:
        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
#        packetparse.writerow(['proto','srcip','sport','dstip','dport','ts','pkt_sz'])
        packetparse.writerow(['srcip','sport','dstip','dport','proto','bytes','year','month','day','hour','minute','sec','date','time'])


def process_packets(scapy_cap):
    for packet in scapy_cap:
        try:
            if packet[TCP]:
                proto     = 'tcp'
                Bytes     = packet[IP].len
                localtime = time.localtime(packet.time)
                date      = time.strftime('%Y-%m-%d', localtime)
                year      = time.strftime('%Y', localtime)
                month     = time.strftime('%m', localtime)
                day       = time.strftime('%d', localtime)

                Time      = time.strftime('%H:%M:%S', localtime)
                hour      = time.strftime('%H', localtime)
                minute    = time.strftime('%M', localtime)
                sec       = time.strftime('%S', localtime)
                try:
                    with open(savefile, 'a', newline='') as csvfile:
                        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                        packetparse.writerow([packet[IP].src,packet[TCP].sport,packet[IP].dst,packet[TCP].dport,proto,Bytes,year,month,day,hour,minute,sec,date,Time])

                except:
                    continue
            elif packet[UDP]:
                proto     = 'udp'
                Bytes     = packet[IP].len
                localtime = time.localtime(packet.time)
                date      = time.strftime('%Y-%m-%d', localtime)
                year      = time.strftime('%Y', localtime)
                month     = time.strftime('%m', localtime)
                day       = time.strftime('%d', localtime)

                Time      = time.strftime('%H:%M:%S', localtime)
                hour      = time.strftime('%H', localtime)
                minute    = time.strftime('%M', localtime)
                sec       = time.strftime('%S', localtime)

                try:
                    with open(savefile, 'a', newline='') as csvfile:
                        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                        packetparse.writerow([packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport,proto,Bytes,year,month,day,hour,minute,sec,date,Time])
                except:
                    continue
        except:
            continue

sniff(iface=sys.argv[1], store=False, prn=process_packets)

