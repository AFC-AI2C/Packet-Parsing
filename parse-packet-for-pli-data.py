#! /usr/bin/env python3

from scapy.all import *
import sys, re, time, csv, datetime, ipaddress, requests
import xml.etree.ElementTree as ET
import psycopg2

"""
Usage:
    Syntax
    ./parse-packet.py file.pcap <ip address>

    Single IP
    ./parse-packet.py 'pli-traffic.pcapng' 192.168.42.110

    Subnet - classful
    ./parse-packet.py 'pli-traffic.pcapng' 192.168.42.0/24

    Subnet - classless
    ./parse-packet.py 'pli-traffic.pcapng' 192.168.42.64/26

    Internal drone IP list (hardcoded within script)
    ./parse-packet.py 'pli-traffic.pcapng' drones

    IP file list (one ip per line)
    ./parse-packet.py 'pli-traffic.pcapng' ip-list.txt

    IP file list (one ip per line)
    ./parse-packet.py <nic_name> ip-list.txt

Description:
    Able to parse network traffic or packet captures for Position Location Information (PLI)
    for drones by using an single IP, Subnet, or IP list.
    Data can be displayed on the terminal, written to a CSV file, or sent to a postgresql database.  
"""

# The directory that PLI data will be saved to
if sys.argv[3]:
    savePath = sys.argv[3] 
else:
    savePath = '/home/coeus/Desktop/PC22/packet-capture/project-4'
command = f"mkdir -p {savePath} 2> /dev/null"
os.system(command)

# Write logs information to file and display on terminal
def writeLog(message):
    # logFile=f"{savePath}/processing-packet.log"
    logFile=f"./processing-packet.log"
    with open(logFile, 'a') as f:
        original_stdout = sys.stdout
        sys.stdout = f
        logEntry=f"[!] {datetime.datetime.now()} -- {message}"
        print(logEntry)
        sys.stdout = original_stdout
        print(logEntry)


# Hard coded internal IPs of drones...
if sys.argv[2] == 'drones':
    ipList=['192.168.42.110','192.168.42.112','192.168.42.114','192.168.42.115','192.168.42.148','192.168.42.149','192.168.42.150']
# IP List is obtained from file sepcified, one IP per line
elif os.path.isfile(sys.argv[2]):
    ipList=[]
    with open(sys.argv[2],'r') as iplist:
        for ip in iplist.readlines():
            ipList.append(ip.strip("\n"))
# Generates IP List from subnet range provided
else:
    ipList=[str(ip) for ip in ipaddress.IPv4Network(sys.argv[2])]


# Removes network and broadcast IPs from list
try:
    if "/" in sys.argv[2]:
        ipList.pop(0)
        ipList.pop()
        writeLog(f"Removed network and broadcast IPs from {sys.argv[2]}")
        writeLog(f"Processing packets for {len(ipList)} IPs from {sys.argv[2]}")

except:
    writeLog(f"Processing packets for IP: {sys.argv[2]}")


# Location of images extracted from within drones
imagesExtracted='images-extracted-from-packets'
command = f"mkdir -p {savePath}/{imagesExtracted} 2> /dev/null"
os.system(command)
writeLog("Checking if images directory exists and creating if necessary")

# Location of images pulled directly from dones
imagesPulled='images-pulled-from-drones'
command = f"mkdir -p {savePath}/{imagesPulled} 2> /dev/null"
os.system(command)
writeLog("Checking if images directory exists and creating if necessary")

# Location of CSV files for drone PLI and Images
saveFilePli     = f"{savePath}/packet-parsed-output-pli.csv"
saveFileImages  = f"{savePath}/packet-parsed-output-images.csv"


if os.path.isfile(saveFileImages):
    pass
else:
    with open(saveFileImages, 'w', newline='') as csvfile:
        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        packetparse.writerow(['proto','srcip','sport','dstip','dport','how ','stale','start','time','etype','uid','version','ce','hae','lat','le','lon','opex','qos','image_uid','parent_callsign','relation','image_url'])
    with open(saveFilePli, 'w', newline='') as csvfile:
        packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        packetparse.writerow(['proto','srcip','sport','dstip','dport','how ','stale','start','time','etype','uid','version','ce','hae','lat','le','lon','callsign','urn','altsrc','geopointsrc','course','speed','murmur'])


def process_packets(scapy_cap):
    # Iterates through each packet
    for ip in ipList:
        # The list of assembled image (in base64) from fragmented packets
        fragReassembledArray = []

        # Used to track fragment payload sizes. It continues to grow if MF flags are detected. Once an MF size of 0 is seen, it will save the previous image to list
        fragmentNumber = 0
        fragmentID = 'none'

        #Used to store framgented packet payloads as they are detected
        frag_reassemble = ''

        # Image count
        imageCount = 0

        for packet in scapy_cap:
            imageDetected = False

            try:
                if packet[IP].src == ip:
                    # print("##################################################")
                    # print(f"PACKET: {packet[IP].src} <--> {packet[IP].dst}")

                    # print(f"UDP: {packet[IP].src}:{packet[UDP].sport} <--> {packet[IP].dst}:{packet[UDP].dport}")
                    # writeLog(f"Processing Packet IP: {ip}")
                    
                    #############
                    ### START ### Extract UDP images
                    #############
                    # Note: UDP is a transport layer network protocol. The transport layer is responsible for getting data from one point on the network to another specific point on the network. 
                    # In that context, UDP is described as an "unreliable" protocol because it makes no guarantees about whether the data sent will actually arrive.
                    # The code below extracts UDP framents and their image payload, then assembles and saves them as an image.
                    # Corrupt of missing parts of the image may occur and is in fact expected due to the nature of UDP.

                    # Extracts the raw IP payload
                    if packet[IP].flags == 'MF':
                        fragmentNumber += 1
                        fragMF = packet[IP].frag*8
                        # writeLog(fragMF)
                        
                        # The IP payload
                        pl = str(packet[IP].payload).lstrip('b')
                        #print(pl)

                        # The first fragmented packet, parses out unneed xml
                        if re.search('<image', pl):
                            fragmentID = packet[IP].id
                            fragFirst = str(''.join(pl.split('">')[-1].split("\\n")).strip("'"))
                            frag_reassemble += fragFirst
                            # print(pl)
                            # print(fragFirst)
                            writeLog(f"Found image within packet within fragmented {len(fragMF)} packets")
                        # The rests of the fragmented packets
                        else:
                            # fragMore = str(pl.strip("'"))
                            fragMore = str(''.join(pl.split('">')[-1].split("\\n")).strip("'"))
                            # print(pl)
                            # print(fragMore)
                            frag_reassemble += fragMore

                    # Adds the remaining last part of the image from the packet within the MF bit
                    elif packet[IP].id == fragmentID:
                        pl = str(packet[IP].payload).lstrip('b')
                        fragmentID = 'none'
                        fragmentNumber = 0
                        fragMore = str(pl.split("</image>")[0].strip("'"))
                        # print(pl)
                        # print(fragMore)
                        frag_reassemble += fragMore

                        if len(frag_reassemble) > 0:
                            # base64 decodes the data and saves it as a png image
                            imageCount += 1
                            saveImage = f"{savePath}/extracted_image_[{ip}]_{str(imageCount).zfill(6)}.png"
                            command   = f"echo '{frag_reassemble}' | base64 -d > {imagesExtracted}/{saveImage}" # 2> /dev/null
                            # print(frag_reassemble)
                            os.system(command)
                            writeLog(f"Saving extracted thumbnail from IP: {ip} -- {saveImage}")

                            # Saves base64 encoded image
                            # command   = f"echo '{frag_reassemble}' > images/image.base64"
                            # os.system(command)

                        # Resets buffer
                        frag_reassemble = ''
                    
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
                    xml_array = ''
                    xml_array = udp_plf.split("\n")
                    # print(xml_array)

                    # help visualize the data in properly formatted xml
                    xml_str = ''
                    for line in xml_array:
                        # New code after XML change
                        if line.startswith('<?'):
                            # Splits the payload xml string into an array
                            lineArray = str(line).split("\\n")

                            # remove trailing null data, ex: "\x00\x00\x00\x00 ...etc"
                            lineArray.pop()

                            for l in lineArray:
                                # print(l)
                                xml_str += f"{l}\n"

                    # print(xml_str)
                    """
                    # Normal PLI Data, may contain imbedded base64 image thumnails
                    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                    <event how="m-f" stale="2022-10-21T03:40:03Z" start="2022-10-20T17:40:03Z" time="2022-10-20T17:40:03Z" type="a-f-G-E-V" uid="TEXTM5-2-MCAS-1SQ7CAVSBU" version="2.0">
                        <point ce="0.5" hae="719.6934814453125" lat="35.35411815769853" le="0.5" lon="-116.56687635867198"/>
                        <detail>
                            <contact callsign="TEXTM5-2-MCAS-1SQ7CAVSBU"/>
                            <uid Droid="TEXTM5-2-MCAS-1SQ7CAVSBU"/>
                            <vmf urn="URN"/>
                            <precisionlocation altsrc="GPS" geopointsrc="GPS"/>
                            <__group role="Team Member" name="Cyan"/>
                            <track course="74.682968611455237" speed="0.0026152134615261115"/>
                            <robot murmur="192.168.42.110:4002"/>
                        </detail>
                    </event>

                    # Data with embedded image url
                    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                    <event how="m-f" opex="s" qos="7-r-c" stale="2022-10-21T03:34:20Z" start="2022-10-20T17:34:20Z" time="2022-10-20T17:34:20Z" type="a-h-G-E-V-A-T-H" uid="ripsawA_100001" version="2.0">
                        <point ce="0" hae="711.16868709969913" lat="35.353569284017858" le="0" lon="-116.57185642484488"/>
                        <detail>
                            <link uid="TEXTM5-2-MCAS-1SQ7CAVSBU" parent_callsign="TEXTM5-2-MCAS-1SQ7CAVSBU" relation="p-p"/>
                            <image url="http://192.168.42.110:4002/threat/ripsawA_100001.png"/>
                        </detail>
                    </event>
                    """
                    ###########
                    ### END ### Formats data into readable xml format
                    ###########
                    

                    proto = 'udp'
                    srcip = SourceIP
                    sport = SourcePort
                    dstip = DestinationIP
                    dport = DestinationPort

                    # print(xml_str)

                    try:
                        if 'opex' in xml_str and 'qos' in xml_str:
                            event = ET.fromstring(xml_str)
                            imageDetected = True
                            print(f"IMG: {packet[IP].src}:{packet[UDP].sport} <--> {packet[IP].dst}:{packet[UDP].dport}")
                            print(xml_str)
                            print('----------')

                            # Creates values for data with urls embedded
                            how = event.attrib["how"]
                            opex = event.attrib["opex"]
                            qos = event.attrib["qos"]
                            stale = event.attrib["stale"]
                            start = event.attrib["start"]
                            time = event.attrib["time"]
                            etype = event.attrib["type"]
                            uid = event.attrib["uid"]
                            version = event.attrib["version"]
                            point = event.find('point')
                            ce = point.attrib["ce"]
                            hae = point.attrib["hae"]
                            lat = point.attrib["lat"]
                            le = point.attrib["le"]
                            lon = point.attrib["lon"]
                            detail = event.find('detail')
                            image_uid = detail.find('link').attrib['uid']
                            parent_callsign = detail.find('link').attrib['parent_callsign']
                            relation = detail.find('link').attrib['relation']
                            image_url = detail.find('image').attrib['url']
                            
                            # print(f"how:             {how}")
                            # print(f"stale:           {stale}")
                            # print(f"start:           {start}")
                            # print(f"time:            {time}")
                            # print(f"etype:           {etype}")
                            # print(f"uid:             {uid}")
                            # print(f"version:         {version}")
                            # print(f"point:           {point}")
                            # print(f"ce:              {ce}")
                            # print(f"hae:             {hae}")
                            # print(f"lat:             {lat}")
                            # print(f"le:              {le}")
                            # print(f"lon:             {lon}")
                            # print(f"detail:          {detail}")
                            # print(f"image_uid:       {image_uid}")
                            # print(f"parent_callsign: {parent_callsign}")
                            # print(f"relation:        {relation}")
                            # print(f"altsrc:          {altsrc}")
                            # print(f"image_url:       {image_url}")

                            # print(f"Parent CallSign: {parent_callsign} - LAT: {lat} - LON: {lon} ")
                            # print("============================")

                            # Writes values to csv file, one line at a time
                            try:
                                writeLog(f"Writing PLI Data To File For IP: {ip}")                
                                with open(saveFileImages, 'a', newline='') as csvfile:
                                    packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                                    packetparse.writerow([proto,srcip,sport,dstip,dport,how ,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,opex,qos,image_uid,parent_callsign,relation,image_url])
                            except:
                                continue

                            # Saves data to postgresql database
                            try:
                                connection = psycopg2.connect(user="postgres",
                                                            password="afc_ai2c",
                                                            host="192.168.20.189",
                                                            port="5432",
                                                            database="pli")
                                cursor = connection.cursor()

                                postgres_insert_query = """ INSERT INTO targets (proto,srcip,sport,dstip,dport,how,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,opex,qos,image_uid,parent_callsign,relation,image_url) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                                record_to_insert = (proto,srcip,sport,dstip,dport,how,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,opex,qos,image_uid,parent_callsign,relation,image_url)
                                cursor.execute(postgres_insert_query, record_to_insert)

                                connection.commit()
                                count = cursor.rowcount
                                print(count, "Record inserted successfully into targets table")

                            except (Exception, psycopg2.Error) as error:
                                print("Failed to insert record into targets table", error)

                            finally:
                                # closing database connection.
                                if connection:
                                    cursor.close()
                                    connection.close()
                                    print("PostgreSQL connection is closed")

                    except:
                        continue


                    try:
                        if not 'opex' in xml_str:
                            event = ET.fromstring(xml_str)
                            # print(f"PLI: {packet[IP].src}:{packet[UDP].sport} <--> {packet[IP].dst}:{packet[UDP].dport}")
                            # print(xml_str)
                            # print('----------')
                            imageDetected = False
                            # Creates values from normal PLI data
                            how = event.attrib["how"]
                            stale = event.attrib["stale"]
                            start = event.attrib["start"]
                            time = event.attrib["time"]
                            etype = event.attrib["type"]
                            uid = event.attrib["uid"]
                            version = event.attrib["version"]
                            point = event.find('point')
                            ce = point.attrib["ce"]
                            hae = point.attrib["hae"]
                            lat = point.attrib["lat"]
                            le = point.attrib["le"]
                            lon = point.attrib["lon"]
                            detail = event.find('detail')
                            callsign = detail.find('contact').attrib['callsign']
                            # droid = detail.find('uid').attrib['Droid']
                            urn = detail.find('vmf').attrib['urn']
                            altsrc = detail.find('precisionlocation').attrib['altsrc']
                            geopointsrc = detail.find('precisionlocation').attrib['geopointsrc']
                            # role = detail.find('__group').attrib['role']
                            # name = detail.find('__group').attrib['name']
                            course = detail.find('track').attrib['course']
                            speed = detail.find('track').attrib['speed']
                            murmur = detail.find('robot').attrib['murmur']

                            # print(f"{[proto,srcip,sport,dstip,dport,how ,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,callsign,urn,altsrc,geopointsrc,course,speed,murmur]}")
                            
                            # Writes values to csv file, one line at a time
                            try:
                                writeLog(f"Writing PLI Data To File For IP: {ip}")                
                                with open(saveFilePli, 'a', newline='') as csvfile:
                                    packetparse = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                                    packetparse.writerow([proto,srcip,sport,dstip,dport,how ,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,callsign,urn,altsrc,geopointsrc,course,speed,murmur])
                            except:
                                continue

                            # Saves data to postgresql database
                            try:
                                connection = psycopg2.connect(user="postgres",
                                                            password="afc_ai2c",
                                                            host="192.168.20.189",
                                                            port="5432",
                                                            database="pli")
                                cursor = connection.cursor()

                                postgres_insert_query = """ INSERT INTO drones (proto,srcip,sport,dstip,dport,how,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,callsign,urn,altsrc,geopointsrc,course,speed,murmur) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
                                record_to_insert = (proto,srcip,sport,dstip,dport,how ,stale,start,time,etype,uid,version,ce,hae,lat,le,lon,callsign,urn,altsrc,geopointsrc,course,speed,murmur)
                                cursor.execute(postgres_insert_query, record_to_insert)

                                connection.commit()
                                count = cursor.rowcount
                                print(count, "Record inserted successfully into drones table")

                            except (Exception, psycopg2.Error) as error:
                                print("Failed to insert record into drones table", error)

                            finally:
                                # closing database connection.
                                if connection:
                                    cursor.close()
                                    connection.close()
                                    print("PostgreSQL connection is closed")

                    except:
                        continue

            except:
                continue
            finally:
                # If an image is detected, this attempts to download the image from the drone
                if imageDetected == True:
                    imageDetected = False
                    try:
                        # downloads images from drone
                        writeLog(f"Saving pulled image from drone: {image_url}")
                        imageFile = requests.get(image_url, allow_redirects=True, timeout=1)
                        filePath=f"{savePath}/{imagesPulled}/{image_url.split('/')[-1]}"
                        open(filePath, 'wb').write(imageFile.content)
                    except:
                        continue



# Importing packets into memory
if os.path.isfile(sys.argv[1]):
    fileSize=os.path.getsize(sys.argv[1])
    fileSizeMB=round(int(fileSize)/1024/1024,3)
    writeLog(f"Importing Packets Into Memory [{fileSizeMB} MB]")
    scapy_cap = rdpcap(sys.argv[1])
    writeLog(f"Finished Importing Packets...")
    time.sleep(2)
    process_packets(scapy_cap)
# Sniffs live packets from the network
else:
    sniff(iface=sys.argv[1], store=False, prn=process_packets)




