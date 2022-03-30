#! /usr/bin/python3

from scapy.all import *
import sys, re, time, csv

"""
usage:
    ./parse-packet.py file.pcap <ip address>
    ./parse-packet.py traffic.pcap 10.0.0.1
    ./parse-packet.py 'LBRR outside Cisco ASA - filtered.pcapng' 10.60.11.11
"""

scapy_cap = rdpcap(sys.argv[1])
# scapy_cap = rdpcap('LBRR outside Cisco ASA - filtered.pcapng')
#scapy_cap = rdpcap('LBRR behind Cisco ASA NAT - multicast udp.pcapng')

#############
### START ### Parse UDP payload for UAV/UGV data 
#############

# The saved image name
savefile  = "packet-parsed-output-[{0}].csv".format(time.strftime("%Y-%m-%d@%H:%M:%S"))
saveImage = ''

command = "mkdir images 2> /dev/null"
os.system(command)

with open(savefile, 'w', newline='') as csvfile:
    packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    packetparse.writerow(['Protocol','SourceIP','SourcePort','DestinationIP','DestinationPort','EventCallSign','How','Opex','QOS','Stale','Start','Time','EventType','UUID','Version','ce','hae','Lat','le','Lon','CallSign','Endpoint','ExtendedCot','Course','Slope','Speed','GimbalPitch','GimbalRoll','GimbalYaw','HomeLat','HomeLon','Azimuth','Elevation','FOV','Model','North','Range','Roll','SensorType','BatteryMaxCapacity','BatteryRemainingCapacity','FlightTime','VehicleType','TypeTag','Voltage','GPS','RSSI','URL','ImageParentCallSign','ImageRelation','ImageLinkUID','ImageHeight','ImageWidth','ImageSize','ImageMime','ImageType','ImageURL','ImageFile'])

    # The list of assembled image (in base64) from fragmented packets
    fragReassembledArray = []

    # Used to track fragment payload sizes. It continues to grow if MF flags are detected. Once an MF size of 0 is seen, it will save the previous image to list
    fragMFnum = 0

    #Used to store framgented packet payloads as they are detected
    frag_reassemble = ''

    # Image count
    imageCount = 0

    # Iterates through each packet
    for packet in scapy_cap:
        try:
            # if packet[IP]:
            if packet[IP].src == sys.argv[2]:
            # if packet[IP] and packet[IP].src == '10.60.11.11':


                #############
                ### START ### Extract UDP images
                #############
                # Note: UDP is a transport layer network protocol. The transport layer is responsible for getting data from one point on the network to another specific point on the network. 
                # In that context, UDP is described as an "unreliable" protocol because it makes no guarantees about whether the data sent will actually arrive.
                # The code below extracts UDP framents and their image payload, then assembles and saves them as an image.
                # Corrupt of missing parts of the image may occur and is in fact expected due to the nature of UDP.
                try:
                    # Extracts the raw IP payload
                    if packet[IP].flags == 'MF':
                        fragMF = packet[IP].frag*8
                        # print(fragMF)
                        
                        # if a new fragment packet is detected, it writes the previous assembled packets to an array
                        if fragMF == 0:
                            if len(frag_reassemble) > 0:
                                # saveImage = "extracted-image-[{0}].png".format(time.strftime("%Y-%m-%d@%H:%M:%S"))
                                imageCount += 1
                                saveImage = "extracted-image-{0}.png".format(str(imageCount).zfill(6))
                                command   = "echo '{0}' | base64 -d > images/{1} 2> /dev/null".format(frag_reassemble,saveImage)
                                # saveTSing = "extracted-image-{0}.txt".format(str(imageCount).zfill(6))
                                # command   = "echo '{0}' > images/{1} 2> /dev/null".format(frag_reassemble,saveTSing)
                                os.system(command)
                            # Resets buffer
                            frag_reassemble = ''

                        # The IP payload
                        pl = str(packet[IP].payload).lstrip('b')
                        #print(pl)
                        # zUbEiQe
                        # Cn0qdUBNTCEYou

                        # The first fragmented packet, parses out unneed xml
                        if re.search('<image', pl):
                            fragFirst = str(''.join(pl.split('">')[-1].split("\\n")).strip("'"))
                            frag_reassemble += fragFirst
                            # print(fragFirst)
                        # The rests of the fragmented packets
                        else:
                            fragMore = str(''.join(pl.split('">')[-1].split("\\n")).strip("'"))
                            frag_reassemble += fragMore
                            # print(fragMore)
                except:
                    continue
                # print(fragReassembledArray)
                # print(len(fragReassembledArray))
                ###########
                ### END ### Extract UDP images
                ###########


                SourceIP        = str(packet[IP].src) 
                SourcePort      = str(packet[UDP].sport)
                DestinationIP   = str(packet[IP].dst)
                DestinationPort = str(packet[UDP].dport)

                udp_pl=packet[UDP].payload
                udp_plf=str(udp_pl).lstrip("b'").rstrip("'").replace('><','>\n<')

                #############
                ### START ### Formats data into readable xml format
                #############
                # print("==================================================")
                # print('UDP: {}:{} <--> {}:{}'.format(SourceIP,SourcePort,DestinationIP,DestinationPort))    
                # print(udp_plf)
                xml_array = ''
                xml_array = udp_plf.split("\n")
                indent    = -1
                # print(xml_array)

                # help visualize the data in properly formatted xml
                xml_str = ''
                for line in xml_array:
                    # print(indent)
                    if line.startswith('</'):
                        xml_str += (indent * "\t") + line + "\n"
                        # print('-1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and line.endswith('/>')):
                        indent += 1
                        xml_str += (indent * "\t") + line + "\n"
                        # print('=1 ' + (indent * "\t") + line)
                        indent -= 1
                    elif (line.startswith('<') and not line.startswith('</')) and re.search("</", line):
                        indent += 1
                        xml_str += (indent * "\t") + line + "\n"
                        # print('=2 ' + (indent * "\t") + line)
                        indent -= 1
                    elif line.startswith('<') and not re.search("</", line):
                        indent += 1
                        xml_str += (indent * "\t") + line + "\n"
                        # print('+1 ' + (indent * "\t") + line)
                    else :
                        xml_str += line + "\n"
                #print(xml_str)

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
                ###########
                ### END ### Formats data into readable xml format
                ###########
                

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

                ImageParentCallSign  = ''
                ImageRelation  = ''
                ImageLinkUID   = ''
                ImageHeight    = ''
                ImageWidth     = ''
                ImageSize      = ''
                ImageMime      = ''
                ImageType      = ''
                ImageURL       = ''
                ImageFile      = ''
                # ImageData      = ''



                #print(xml_array)
                # for line in xml_array:
                    # Couldn't get the above to parse out '<link' and '<image'... changed to alternative method below
                # print(xml_str.splitlines())
                for line in xml_str.splitlines():
                    # print(line)
                    if re.search('\s+<event', line) and re.search('callsign', line):
                        event         = line.strip().lstrip('<event').rstrip('>').split()
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
                    elif re.search('\s+<point', line):
                        point = line.strip().lstrip('<point').rstrip('/>').split()
                        ce    = point[0].split('=')[1].strip('"')
                        hae   = point[1].split('=')[1].strip('"')
                        Lat   = point[2].split('=')[1].strip('"')
                        le    = point[3].split('=')[1].strip('"')
                        Lon   = point[4].split('=')[1].strip('"')
                    elif re.search('\s+<contact', line):
                        contact   = line.strip().lstrip('<contact').rstrip('/>').split()
                        CallSign  = contact[0].split('=')[1].strip('"')
                        Endpoint  = contact[1].split('=')[1].strip('"')
                    elif re.search('\s+<_uastool', line):
                        uastool      = line.strip().lstrip('<_uastool').rstrip('/>').split()
                        ExtendedCot  = uastool[0].split('=')[1].strip('"')
                    elif re.search('\s+<track', line):
                        track   = line.strip().lstrip('<track').rstrip('/>').split()
                        Course  = track[0].split('=')[1].strip('"')
                        Slope   = track[1].split('=')[1].strip('"')
                        Speed   = track[2].split('=')[1].strip('"')
                    elif re.search('\s+<_DJI_', line):
                        DJI          = line.strip().lstrip('<_DJI_').rstrip('/>').split()
                        GimbalPitch  = DJI[0].split('=')[1].strip('"')
                        GimbalRoll   = DJI[1].split('=')[1].strip('"')
                        GimbalYaw    = DJI[2].split('=')[1].strip('"')
                        HomeLat      = DJI[3].split('=')[1].strip('"')
                        HomeLon      = DJI[4].split('=')[1].strip('"')
                    elif re.search('\s+<sensor', line):
                        sensor     = line.strip().lstrip('<sensor').rstrip('/>').split()
                        Azimuth    = sensor[0].split('=')[1].strip('"')
                        Elevation  = sensor[1].split('=')[1].strip('"')
                        FOV        = sensor[2].split('=')[1].strip('"')
                        Model      = sensor[3].split('=')[1].strip('"')
                        North      = sensor[4].split('=')[1].strip('"')
                        Range      = sensor[5].split('=')[1].strip('"')
                        Roll       = sensor[6].split('=')[1].strip('"')
                        SensorType = sensor[7].split('=')[1].strip('"')
                    elif re.search('\s+<vehicle', line):
                        vehicle                  = line.strip().lstrip('<vehicle').rstrip('/>').split()
                        BatteryMaxCapacity       = vehicle[0].split('=')[1].strip('"')
                        BatteryRemainingCapacity = vehicle[1].split('=')[1].strip('"')
                        FlightTime               = vehicle[2].split('=')[1].strip('"')
                        VehicleType              = vehicle[3].split('=')[1].strip('"')
                        TypeTag                  = vehicle[4].split('=')[1].strip('"')
                        Voltage                  = vehicle[5].split('=')[1].strip('"')
                    elif re.search('\s+<_radio', line):
                        radio = line.strip().lstrip('<_radio').rstrip('/>').split()
                        GPS   = radio[0].split('=')[1].strip('"')
                        RSSI  = radio[1].split('=')[1].strip('"')
                    elif re.search('\s+<__video', line):
                        video = line.strip().lstrip('<__video').rstrip('/>').split()
                        URL   = video[0].split('=')[1].strip('"')
                    elif re.search('\s+<event', line) and not re.search('callsign', line):
                        event         = line.strip().lstrip('<event').rstrip('>').split()
                        How           = event[0].split('=')[1].strip('"')
                        Opex          = event[1].split('=')[1].strip('"')
                        QOS           = event[2].split('=')[1].strip('"')
                        Stale         = event[3].split('=')[1].strip('"')
                        Start         = event[4].split('=')[1].strip('"')
                        Time          = event[5].split('=')[1].strip('"')
                        EventType     = event[6].split('=')[1].strip('"')
                        UUID          = event[7].split('=')[1].strip('"')
                        Version       = event[8].split('=')[1].strip('"')
                    elif re.search('\s+<link', line):
                        link                = line.strip().lstrip().lstrip('<link').rstrip('/>').split()
                        ImageParentCallSign = link[0].split('=')[1].strip('"')
                        ImageRelation       = link[1].split('=')[1].strip('"')
                        ImageLinkUID        = link[2].split('=')[1].strip('"')
                    elif re.search('\s+<image',line):
                        image         = line.strip().lstrip('<image').split('">')
                        ImageProperty = image[0].strip().split()
                        ImageHeight   = ImageProperty[0].split('=')[1].strip('"')
                        ImageMime     = ImageProperty[1].split('=')[1].strip('"')
                        ImageSize     = ImageProperty[2].split('=')[1].strip('"')
                        ImageType     = ImageProperty[3].split('=')[1].strip('"')
                        ImageURL      = ImageProperty[4].split('=')[1].strip('"')
                        ImageWidth    = ImageProperty[5].split('=')[1].strip('"')
                        #ImageData     = image[1]
                        ImageFile     = saveImage
                    
                    # elif re.search('<?', line) or re.search('\s+<', line):
                    #     continue
                    # else:
                    #     print(line)

                packetparse.writerow(['UDP',SourceIP,SourcePort,DestinationIP,DestinationPort,EventCallSign,How,Opex,QOS,Stale,Start,Time,EventType,UUID,Version,ce,hae,Lat,le,Lon,CallSign,Endpoint,ExtendedCot,Course,Slope,Speed,GimbalPitch,GimbalRoll,GimbalYaw,HomeLat,HomeLon,Azimuth,Elevation,FOV,Model,North,Range,Roll,SensorType,BatteryMaxCapacity,BatteryRemainingCapacity,FlightTime,VehicleType,TypeTag,Voltage,GPS,RSSI,URL,ImageParentCallSign,ImageRelation,ImageLinkUID,ImageHeight,ImageWidth,ImageSize,ImageMime,ImageType,ImageURL,ImageFile])

        except:
            continue


        # Currently not parsing any TCP packets
        # try:
        #     if packet[TCP] and packet[IP].src == sys.argv[1] :
        #         src_ip=str(packet[IP].src) 
        #         src_pt=str(packet[TCP].sport)
        #         dst_ip=str(packet[IP].dst)
        #         dst_pt=str(packet[TCP].dport)

        #         tcp_pl=packet[TCP].payload

        #         print("==================================================")
        #         print('TCP: {}:{} <--> {}:{}'.format(src_ip,src_pt,dst_ip,dst_pt))    
        #         print(tcp_pl)
        # except:
        #     continue

###########
### END ### Parse UDP payload for UAV/UGV data 
###########




