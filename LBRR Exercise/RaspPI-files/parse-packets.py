#! /usr/bin/python3

from scapy.all import *
import os, sys, re, time, csv

"""
usage:
    ./parse-packet.py file.pcap <ip address>
    ./parse-packet.py traffic.pcap 10.0.0.1
    ./parse-packet.py 'LBRR outside Cisco ASA - filtered.pcapng' 10.60.11.11

Argument 1 / sys.argv[1]
    Is the pcap to process
Argument 2 / sys.argv[2]
    Is the IP src to process

"""

# The pcap to process
scapy_cap = rdpcap(sys.argv[1])
# scapy_cap = rdpcap('test_packet.pcapng')

fname = str(os.path.basename(sys.argv[1])).rstrip(".pcap")
#savefile = './csvs/' + time.strftime("%Y-%m-%d@%H:%M:%S") + '_' + fname + '.csv'
savefile = './csvs/' + fname + '.csv'

with open(savefile, 'w', newline='') as csvfile :
    packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    packetparse.writerow(['Protocol','SourceIP','SourcePort','DestinationIP','DestinationPort','EventCallSign','How','Opex','QOS','Stale','Start','Time','EventType','UUID','Version','ce','hae','Lat','le','Lon','CallSign','Endpoint','ExtendedCot','Course','Slope','Speed','GimbalPitch','GimbalRoll','GimbalYaw','HomeLat','HomeLon','Azimuth','Elevation','FOV','Model','North','Range','Roll','SensorType','BatteryMaxCapacity','BatteryRemainingCapacity','FlightTime','VehicleType','TypeTag','Voltage','GPS','RSSI','URL'])

    for packet in scapy_cap :
        try :
            if packet[UDP] and packet[IP].src == sys.argv[2] :
            # if packet[UDP] and packet[IP].src == '172.20.206.48' :

                SourceIP        = str(packet[IP].src)
                SourcePort      = str(packet[UDP].sport)
                DestinationIP   = str(packet[IP].dst)
                DestinationPort = str(packet[UDP].dport)

                udp_pl  = packet[UDP].payload
                udp_plf = str(udp_pl).lstrip("b'").rstrip("'").replace('><','>\n<')

                # print("==================================================")
                # print('UDP: {}:{} <--> {}:{}'.format(SourceIP,SourcePort,DestinationIP,DestinationPort))
                # print(udp_plf)
                xml_str = ''
                xml_str = udp_plf.split("\n")
                indent  = -1
                xml_pl  =  ''


                for line in xml_str :
                    # print(indent)
                    if line.startswith('</') :
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('-1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and line.endswith('/>')) :
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('=1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and not line.startswith('</')) and re.search("</", line) :
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('=2 ' + (indent * "\t") + line)
                        indent -= 1
                    elif line.startswith('<') and not re.search("</", line) :
                        indent += 1
                        xml_pl += (indent * "\t") + line + "\n"
                        # print('+1 ' + (indent * "\t") + line)

                # print(xml_pl)


                EventCallSign = ''
                How           = ''
                Opex          = ''
                QOS           = ''
                Stale         = ''
                Start         = ''
                Time          = ''
                EventType     = ''
                UUID          = ''
                Version       = ''
                ce            = ''
                hae           = ''
                Lat           = ''
                le            = ''
                Lon           = ''
                How           = ''
                CallSign      = ''
                Endpoint      = ''
                ExtendedCot   = ''
                Course        = ''
                Slope         = ''
                Speed         = ''
                GimbalPitch   = ''
                GimbalRoll    = ''
                GimbalYaw     = ''
                HomeLat       = ''
                HomeLon       = ''
                Azimuth       = ''
                Elevation     = ''
                FOV           = ''
                Model         = ''
                North         = ''
                Range         = ''
                Roll          = ''
                SensorType    = ''
                BatteryMaxCapacity        = ''
                BatteryRemainingCapacity  = ''
                FlightTime    = ''
                VehicleType   = ''
                TypeTag       = ''
                Voltage       = ''
                GPS           = ''
                RSSI          = ''
                URL           = ''

                for line in xml_str :

                    if line.startswith('<event') :
                        event = line.lstrip('<event').rstrip('>').split()
                        EventCallSign = event[0].split('=')[1].strip('"')
                        How           = event[1].split('=')[1].strip('"')
                        Opex          = event[2].split('=')[1].strip('"')
                        QOS           = event[3].split('=')[1].strip('"')
                        Stale         = event[4].split('=')[1].strip('"')
                        Start         = event[5].split('=')[1].strip('"')
                        Time          = event[6].split('=')[1].strip('"')
                        EventType     = event[7].split('=')[1].strip('"')
                        UUID          = event[8].split('=')[1].strip('"')
                        Version       = event[9].split('=')[1].strip('"')
                    if line.startswith('<point') :
                        point = line.lstrip('<point').rstrip('/>').split()
                        ce   = point[0].split('=')[1].strip('"')
                        hae  = point[1].split('=')[1].strip('"')
                        Lat  = point[2].split('=')[1].strip('"')
                        le   = point[3].split('=')[1].strip('"')
                        Lon  = point[4].split('=')[1].strip('"')
                    if line.startswith('<contact') :
                        contact = line.lstrip('<contact').rstrip('/>').split()
                        CallSign  = contact[0].split('=')[1].strip('"')
                        Endpoint  = contact[1].split('=')[1].strip('"')
                    if line.startswith('<_uastool') :
                        uastool = line.lstrip('<_uastool').rstrip('/>').split()
                        ExtendedCot  = uastool[0].split('=')[1].strip('"')
                    if line.startswith('<track') :
                        track = line.lstrip('<track').rstrip('/>').split()
                        Course  = track[0].split('=')[1].strip('"')
                        Slope   = track[1].split('=')[1].strip('"')
                        Speed   = track[2].split('=')[1].strip('"')
                    if line.startswith('<_DJI_') :
                        DJI = line.lstrip('<_DJI_').rstrip('/>').split()
                        GimbalPitch  = DJI[0].split('=')[1].strip('"')
                        GimbalRoll   = DJI[1].split('=')[1].strip('"')
                        GimbalYaw    = DJI[2].split('=')[1].strip('"')
                        HomeLat      = DJI[3].split('=')[1].strip('"')
                        HomeLon      = DJI[4].split('=')[1].strip('"')
                    if line.startswith('<sensor') :
                        sensor = line.lstrip('<sensor').rstrip('/>').split()
                        Azimuth    = sensor[0].split('=')[1].strip('"')
                        Elevation  = sensor[1].split('=')[1].strip('"')
                        FOV        = sensor[2].split('=')[1].strip('"')
                        Model      = sensor[3].split('=')[1].strip('"')
                        North      = sensor[4].split('=')[1].strip('"')
                        Range      = sensor[5].split('=')[1].strip('"')
                        Roll       = sensor[6].split('=')[1].strip('"')
                        SensorType = sensor[7].split('=')[1].strip('"')
                    if line.startswith('<vehicle') :
                        vehicle = line.lstrip('<vehicle').rstrip('/>').split()
                        BatteryMaxCapacity       = vehicle[0].split('=')[1].strip('"')
                        BatteryRemainingCapacity = vehicle[1].split('=')[1].strip('"')
                        FlightTime               = vehicle[2].split('=')[1].strip('"')
                        VehicleType              = vehicle[3].split('=')[1].strip('"')
                        TypeTag                  = vehicle[4].split('=')[1].strip('"')
                        Voltage                  = vehicle[5].split('=')[1].strip('"')
                    if line.startswith('<_radio') :
                        radio = line.lstrip('<_radio').rstrip('/>').split()
                        GPS   = radio[0].split('=')[1].strip('"')
                        RSSI  = radio[1].split('=')[1].strip('"')
                    if line.startswith('<__video') :
                        video = line.lstrip('<__video').rstrip('/>').split()
                        URL   = video[0].split('=')[1].strip('"')

                packetparse.writerow(['UDP',SourceIP,SourcePort,DestinationIP,DestinationPort,EventCallSign,How,Opex,QOS,Stale,Start,Time,EventType,UUID,Version,ce,hae,Lat,le,Lon,CallSign,Endpoint,ExtendedCot,Course,Slope,Speed,GimbalPitch,GimbalRoll,GimbalYaw,HomeLat,HomeLon,Azimuth,Elevation,FOV,Model,North,Range,Roll,SensorType,BatteryMaxCapacity,BatteryRemainingCapacity,FlightTime,VehicleType,TypeTag,Voltage,GPS,RSSI,URL])
        except :
            continue

### No need to process TCP packets at the moment
#        try :
#            if packet[TCP] and packet[IP].src == sys.argv[1] :
#                src_ip=str(packet[IP].src)
#                src_pt=str(packet[TCP].sport)
#                dst_ip=str(packet[IP].dst)
#                dst_pt=str(packet[TCP].dport)
#
#                tcp_pl=packet[TCP].payload
#
#                print("==================================================")
#                print('TCP: {}:{} <--> {}:{}'.format(src_ip,src_pt,dst_ip,dst_pt))
#                print(tcp_pl)
#        except :
#            continue


### Checks if the CSV file is empty, if so it is deleted
#print(savefile)
file = open(savefile, "r")
line_count = 0
for line in file :
    if line != "\n" :
        line_count += 1
file.close()

if line_count == 1 :
	command = "rm -f {0}".format(savefile)
	os.system(command)
	print('Removing:   [empty CSV File] ' + savefile)


