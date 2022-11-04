#!/usr/bin/env python3

import psycopg2
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
        packetparse.writerow(['srcip','sport','dstip','dport','proto','bytes','datetime','year','month','day','hour','minute','sec','date','time'])


def process_packets(scapy_cap):
    for packet in scapy_cap:
        #try:
        #    #if packet[TCP].dport:
        #        print(f"TCP: {packet[IP].src}")
        #        #proto     = 'tcp'
        #        #Bytes     = packet[IP].len
        #        #localtime = time.localtime(packet.time)
        #        #date      = time.strftime('%Y-%m-%d', localtime)
        #        #year      = time.strftime('%Y', localtime)
        #        #month     = time.strftime('%m', localtime)
        #        #day       = time.strftime('%d', localtime)

        #        #Time      = time.strftime('%H:%M:%S', localtime)
        #        #hour      = time.strftime('%H', localtime)
        #        #minute    = time.strftime('%M', localtime)
        #        #sec       = time.strftime('%S', localtime)
        #        #try:
        #        #    with open(savefile, 'a', newline='') as csvfile:
        #        #        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        #        #        packetparse.writerow([packet[IP].src,packet[TCP].sport,packet[IP].dst,packet[TCP].dport,proto,Bytes,year,month,day,hour,minute,sec,date,Time])

        #        #except:
        #        #    continue
        #except:
        #    continue
        try:
            if packet[UDP].dport:
                #print(f"UDP: {packet[IP].src}")
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
                datetime  = time.strftime('%Y-%m-%d %H:%M:%S',localtime)

                # Outputs to standard out, useful for visualization and sending out over network with cn
                line=str([packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport,proto,Bytes,datetime,year,month,day,hour,minute,sec,date,Time]).lstrip('[').rstrip(']').replace("'","").replace(", ",",")
                print(line)
                
                # # Writes data to local .csv file
                #try:
                #    with open(savefile, 'a', newline='') as csvfile:
                #        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                #        packetparse.writerow([packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport,proto,Bytes,year,month,day,hour,minute,sec,date,Time])
                #except:
                #    continue
                
                # Writes data to postgressql database
                try:
                    #import psycopg2

                    connection = psycopg2.connect(user="postgres",
                                                 password="afc_ai2c",
                                                 host="192.168.42.224",
                                                 port="5432",
                                                 database="netstat")
                    cursor = connection.cursor()

                    postgres_insert_query = """ INSERT INTO traffic (srcip,sport,dstip,dport,proto,bytes,datetime,year,month,day,hour,minute,sec,date,time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                    record_to_insert = (packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport,proto,Bytes,datetime,year,month,day,hour,minute,sec,date,Time)
                    cursor.execute(postgres_insert_query, record_to_insert)

                    connection.commit()
                    count = cursor.rowcount
                    print(count, "Record inserted successfully into traffic table")

                except (Exception, psycopg2.Error) as error:
                    print("Failed to insert record into traffic table", error)
                finally:
                    # closing database connection.
                    if connection:
                        cursor.close()
                        connection.close()
                        print("PostgreSQL connection is closed")
        except:
            continue

sniff(iface=sys.argv[1], store=False, prn=process_packets)

