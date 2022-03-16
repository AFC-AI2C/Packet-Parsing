#! /usr/bin/python3

import sys
from scapy.all import *
import re
import csv


# scapy_cap = rdpcap('test.pcapng')
scapy_cap = rdpcap('LBRR outside Cisco ASA - filtered.pcapng')
#scapy_cap = rdpcap('LBRR behind Cisco ASA NAT - multicast udp.pcapng')


with open('output.csv', 'w', newline='') as csvfile:
    spamwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    spamwriter.writerow(['proto','src_ip', 'src_pt', 'dst_ip', 'dst_pt','ce','hae','lat','le','lon'])

    for packet in scapy_cap:

        try:
            if packet[UDP] and packet[IP].src == sys.argv[1]:
            # if packet[UDP] and packet[IP].src == '172.20.206.48':
                
                src_ip=str(packet[IP].src) 
                src_pt=str(packet[UDP].sport)
                dst_ip=str(packet[IP].dst)
                dst_pt=str(packet[UDP].dport)

                udp_pl=packet[UDP].payload
                udp_plf=str(udp_pl).lstrip("b'").rstrip("'").replace('><','>\n<')

                print("==================================================")
                print('UDP: {}:{} <--> {}:{}'.format(src_ip,src_pt,dst_ip,dst_pt))    
                # print(udp_plf)
                xml_str=''
                xml_str=udp_plf.split("\n")
                indent = -1
                xml_pl = ''



                for line in xml_str:
                    # print(indent)
                    if line.startswith('</'):
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('-1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and line.endswith('/>')):
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('=1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and not line.startswith('</')) and re.search("</", line):
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('=2 ' + (indent * "\t") + line)
                        indent -= 1
                    elif line.startswith('<') and not re.search("</", line):
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('+1 ' + (indent * "\t") + line)

                print(xml_pl)

                lat=''    
                # xml_pl=xml_pl.split("\n")
                for line in xml_str:
                    if line.startswith('<point'):
                        point=line.lstrip('<point').rstrip('/>').split()
                        # print(point)
                        ce  = point[0].split('=')[1]
                        hae = point[1].split('=')[1]
                        lat = point[2].split('=')[1]
                        le  = point[3].split('=')[1]
                        lon = point[4].split('=')[1]

                spamwriter.writerow(['udp',src_ip,src_pt,dst_ip,dst_pt,ce,hae,lat,le,lon])

        except:
            continue

        try:
            if packet[TCP] and packet[IP].src == sys.argv[1] :
                src_ip=str(packet[IP].src) 
                src_pt=str(packet[TCP].sport)
                dst_ip=str(packet[IP].dst)
                dst_pt=str(packet[TCP].dport)

                tcp_pl=packet[TCP].payload

                print("==================================================")
                print('TCP: {}:{} <--> {}:{}'.format(src_ip,src_pt,dst_ip,dst_pt))    
                print(tcp_pl)
        except:
            continue


    # print(blackboxprotobuf.decode_message('uuid:0021ca00-1dd2-11b2-b44b-0022f3893201'))
# protofile='file.txt'
# with open(protofile, 'rb') as f:
#    pb = f.read()

"""
<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
                <soap:Header>
                        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
                        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action>
                        <wsa:MessageID>urn:uuid:15cc822e-f5d7-4414-a7dc-dce3d9f6d1da</wsa:MessageID>
##### Note: no Authentication Header observed #####
                </soap:Header>
                <soap:Body>
                        <wsd:Resolve>
                                <wsa:EndpointReference>
                                        <wsa:Address>uuid:0021ca00-1dd2-11b2-b44b-0022f3893201</wsa:Address>
                                </wsa:EndpointReference>
                        </wsd:Resolve>
                </soap:Body>
        </soap:Envelope>
"""


