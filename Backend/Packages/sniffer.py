import json
import threading

from app import socket_, app
from flask import request, send_file
from flask_socketio import emit
from scapy.all import *

temp_packets = []
Packets = []
Devices = []
SPEED = []
InstantaneousSPEED = []
StartTime = None
Continue = False
GetDevices = False
LOCK = threading.Lock()
DELAY = 1
FILTERS = []
AnalyzedData = []
PaginationPackets = None


def extractPacketProtocols(packet_json):
    try:
        Protocol_Already_Exists = False
        for i in range(2, 5):
            Protocol_Already_Exists = False
            if len(packet_json["Frame_info"]["Frame_protocols"]) > i and packet_json["Frame_info"]["Frame_protocols"][
                i] != "Raw":
                for j in AnalyzedData:
                    if j["name"] == packet_json["Frame_info"]["Frame_protocols"][i]:
                        j["count"] += 1
                        Protocol_Already_Exists = True
                        break
                if not Protocol_Already_Exists:
                    AnalyzedData.append({
                        "name": packet_json["Frame_info"]["Frame_protocols"][i],
                        "count": 1
                    })

        if packet_json["Frame_info"]["Application_protocol"] != "Unknown":
            for j in AnalyzedData:
                if j["name"] == packet_json["Frame_info"]["Application_protocol"]:
                    j["count"] += 1
                    Protocol_Already_Exists = True
                    break

            if not Protocol_Already_Exists:
                AnalyzedData.append({
                    "name": packet_json["Frame_info"]["Application_protocol"],
                    "count": 1
                })
    except:
        # print("Error in Extracting Packet Protocols")
        pass


def extractDeviceFromPacket(packet_json):
    try:
        device = {
            "Mac Address": packet_json["Ethernet"]["src"],
            "Interface": packet_json["Frame_info"]["interfaceId"],
            "IP Address": packet_json["IP"]["src"],
            "Connected to": [packet_json["Ethernet"]["dst"], ]
        }
        deviceAlreadyExists = False
        for i in Devices:
            if i["Mac Address"] == device["Mac Address"]:
                deviceAlreadyExists = True
                if device["Mac Address"] not in i["Connected to"] and device["Mac Address"] != i["Mac Address"]:
                    i["Connected to"].append(device["Mac Address"])
                break

        if not deviceAlreadyExists:
            Devices.append(device)
    except:
        # print("Error in Extracting Device From Packet")
        pass


def getTheSpeedOfEachDevice(packet_json):
    try:
        deviceAlreadyExists = False
        for i in range(len(SPEED)):
            if SPEED[i]["Mac Address"] == packet_json["Ethernet"]["src"]:
                deviceAlreadyExists = True
                InstantaneousSPEED[i]["SBytes"] += packet_json["Frame_info"]["Frame_size"]
                SPEED[i]["SBytes"] += packet_json["Frame_info"]["Frame_size"]
                SPEED[i]["sentPackets"] += 1
            elif SPEED[i]["Mac Address"] == packet_json["Ethernet"]["dst"]:
                InstantaneousSPEED[i]["RBytes"] += packet_json["Frame_info"]["Frame_size"]
                SPEED[i]["RBytes"] += packet_json["Frame_info"]["Frame_size"]
                SPEED[i]["receivedPackets"] += 1

        if not deviceAlreadyExists:
            temp = len(SPEED)
            InstantaneousSPEED.append({
                "Mac Address": packet_json["Ethernet"]["src"],
                "SBytes": packet_json["Frame_info"]["Frame_size"],
                "RBytes": 0,
            })
            SPEED.append({
                "Mac Address": packet_json["Ethernet"]["src"],
                "SBytes": packet_json["Frame_info"]["Frame_size"],
                "RBytes": 0,
                "sentPackets": 1,
                "receivedPackets": 0,
            })
    except:
        # print("Error in speed", packet_json)
        pass


def applyFilters(packet_json):
    global FILTERS
    Application_Layer_Filter = True
    Transport_Layer_Filter = True
    General_Filter = True
    if len(FILTERS) > 0:
        applicationFilters = filter(lambda x: x["checked"] == True, FILTERS[0]["options"])
        applicationFilters = list(map(lambda x: x["value"].lower(), applicationFilters))

        transportFilters = filter(lambda x: x["checked"] == True, FILTERS[1]["options"])
        transportFilters = list(map(lambda x: x["value"].lower(), transportFilters))

        generalFilters = list(filter(lambda x: x["checked"] == True, FILTERS[2]["options"]))

        if packet_json["Frame_info"]["Application_protocol"].lower() not in applicationFilters and len(
                applicationFilters) > 0:
            Application_Layer_Filter = False
        if not Application_Layer_Filter:
            for i in packet_json["Frame_info"]["Frame_protocols"]:
                if i.lower() in applicationFilters:
                    Application_Layer_Filter = True
                    break
        if 'other' in applicationFilters:
            Application_Layer_Filter = True

        if len(transportFilters) > 0:
            Transport_Layer_Filter = False
        for y in packet_json["Frame_info"]["Frame_protocols"]:
            if y.lower() in transportFilters:
                Transport_Layer_Filter = True

        try:
            if len(generalFilters) > 0:
                General_Filter = False
            for z in generalFilters:
                if "sourceip" == z["value"].lower():
                    try:
                        if packet_json["IP"]["src"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                elif "destinationip" == z["value"].lower():
                    try:
                        if packet_json["IP"]["dst"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                elif "sourceport" == z["value"].lower():
                    try:
                        if packet_json["TCP"]["sport"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                    try:
                        if packet_json["UDP"]["sport"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                elif "destinationport" == z["value"].lower():
                    try:
                        if packet_json["TCP"]["dport"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                    try:
                        if packet_json["UDP"]["dport"] == z["inputValue"]:
                            General_Filter = True
                            break
                    except:
                        pass
                elif "sourceaddress" == z["value"].lower():
                    if packet_json["Ethernet"]["src"] == z["inputValue"]:
                        General_Filter = True
                        break
                elif "destinationaddress" == z["value"].lower():
                    if packet_json["Ethernet"]["dst"] == z["inputValue"]:
                        General_Filter = True
                        break
        except:
            pass
    return Application_Layer_Filter and Transport_Layer_Filter and General_Filter


class Sniffer:
    def __get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break

            yield layer
            counter += 1

    def __get_device_type(self, packet):
        for layer in self.__get_packet_layers(packet):
            if layer.name == "Ethernet":
                if layer.dst == "ff:ff:ff:ff:ff:ff":
                    return "Broadcast"
                elif layer.dst.startswith("01:00:5e"):
                    return "Multicast"
                else:
                    return "Unicast"

        return "Unknown"

    def __get_frame_info_json(self, packet):
        packet_json = {}
        try:
            packet_json["interfaceId"] = packet.sniffed_on
        except:
            packet_json["interfaceId"] = ""
        try:
            packet_json["deviceType"] = self.__get_device_type(packet)
        except:
            packet_json["deviceType"] = ""
        try:
            packet_json["Encapsulation_type"] = packet.type
        except:
            packet_json["Encapsulation_type"] = ""
        try:
            packet_json["Arrival_time"] = float(packet.time)
        except:
            packet_json["Arrival_time"] = ""

        try:
            packet_json["sent_time"] = packet.sent_time
        except:
            packet_json["sent_time"] = ""
        try:
            packet_json["Time_shift"] = float(packet_json["Arrival_time"]) - float(packet_json["sent_time"])
        except:
            packet_json["Time_shift"] = ""
        try:
            packet_json["Frame_length"] = packet.len
        except:
            packet_json["Frame_length"] = ""
        try:
            packet_json["Frame_number"] = packet.number
        except:
            packet_json["Frame_number"] = ""
        try:
            packet_json["Capture_length"] = packet.len
        except:
            packet_json["Capture_length"] = ""

        try:
            payload = str(packet.payload)
            # print("Payload: ",payload)
            if 'http' in payload:
                packet_json["Application_protocol"] = "HTTP"
            elif 'ftp' in payload:
                packet_json["Application_protocol"] = "FTP"
            elif 'ssh' in payload:
                packet_json["Application_protocol"] = "SSH"
            elif 'telnet' in payload:
                packet_json["Application_protocol"] = "TELNET"
            elif 'smtp' in payload:
                packet_json["Application_protocol"] = "SMTP"
            elif payload.startswith("GET"):
                packet_json["Application_protocol"] = "HTTP"
            elif payload.startswith("POST"):
                packet_json["Application_protocol"] = "HTTP"
            elif payload.startswith("PUT"):
                packet_json["Application_protocol"] = "HTTP"
            elif payload.startswith("DELETE"):
                packet_json["Application_protocol"] = "HTTP"
            elif payload.startswith("220"):
                packet_json["Application_protocol"] = "FTP"
            elif payload.startswith("HELO"):
                packet_json["Application_protocol"] = "SMTP"
            else:
                packet_json["Application_protocol"] = "Unknown"

        except:
            packet_json["Application_protocol"] = ""

        try:
            packet_json["Frame_protocols"] = ["Frame_info", ]
            temp_layers = [layer.name for layer in self.__get_packet_layers(packet)]
            packet_json["Frame_protocols"].extend(temp_layers)
        except:
            packet_json["Frame_protocols"] = []
        try:
            packet_json["Frame_checksum"] = packet.chksum
        except:
            packet_json["Frame_checksum"] = ""

        try:
            packet_json["Frame_info"] = packet.info
        except:
            packet_json["Frame_info"] = ""

        try:
            packet_json["Frame_size"] = len(packet)
        except:
            packet_json["Frame_size"] = 0

        return packet_json

    def create_packet_json(self, packet):
        packet_json = {}
        packet_json["Frame_info"] = (self.__get_frame_info_json(packet))

        for layer in self.__get_packet_layers(packet):
            layer_json = {}
            # layer_json["name"] = layer.name
            layer_json = {}

            for field in layer.fields_desc:
                layer_json[field.name] = str(getattr(layer, field.name))
            # try:
            #     if layer_json["fields"]["flags"]:
            #         layer_json["fields"]["flags"] = str(layer_json["fields"]["flags"])
            # except:
            #     pass
            # print(layer_json["fields"])
            layerName = layer.name
            for i in packet_json["Frame_info"]["Frame_protocols"]:
                try:
                    temp = i.split("_")[:-1].join("_")
                    if temp == layerName and i not in packet_json.keys():
                        layerName = i
                except:
                    pass
            packet_json[layerName] = layer_json

        return (packet_json)

    def start(self, interface):
        global StartTime, SPEED, InstantaneousSPEED, Devices, AnalyzedData, Packets, temp_packets
        try:
            StartTime = time.time()
            SPEED = []
            InstantaneousSPEED = []
            Devices = []
            AnalyzedData = []
            Packets = []
            temp_packets = []

            def print_layers(packet):
                global temp_packets, Packets, Continue, Devices, LOCK
                # print(self.create_packet_json(packet))

                packet_json = self.create_packet_json(packet)
                LOCK.acquire()
                if packet_json["Frame_info"]["deviceType"] != "Broadcast":
                    extractDeviceFromPacket(packet_json)
                    getTheSpeedOfEachDevice(packet_json)
                extractPacketProtocols(packet_json)
                if applyFilters(packet_json):
                    temp_packets.append(packet_json)
                Packets.append(packet)

                # print(len(temp_packets))
                LOCK.release()
                # print(Devices)

            def stopFilter(packet):
                global Continue
                return not Continue

            sniff(prn=print_layers, iface=interface, stop_filter=stopFilter, store=0, promisc=True)
        except:
            startTime = None
    # def getDevices(self):
    #     global Packets


def dataGenerator(interface):
    global Continue, temp_packets, Packets, LOCK
    print("Initialising")
    threading.Thread(target=Sniffer().start, args=(interface,)).start()

    while Continue:
        try:
            while len(temp_packets) == 0 and Continue:
                socket_.sleep(DELAY)
            LOCK.acquire()
            for i in range(len(SPEED)):
                InstantaneousSPEED[i]["instantanouesRSpeed"] = InstantaneousSPEED[i]["RBytes"] / float(DELAY)
                InstantaneousSPEED[i]["instantanouesSSpeed"] = InstantaneousSPEED[i]["SBytes"] / float(DELAY)
                if time.time() - StartTime:
                    SPEED[i]['avgRSpeed'] = SPEED[i]['RBytes'] / (time.time() - StartTime)
                    SPEED[i]['avgSSpeed'] = SPEED[i]['SBytes'] / (time.time() - StartTime)
                else:
                    SPEED[i]['avgRSpeed'] = SPEED[i]['RBytes']
                    SPEED[i]['avgSSpeed'] = SPEED[i]['SBytes']
            socket_.emit('packet', {
                'data': json.dumps(temp_packets),
                'InstantaneousSPEED': InstantaneousSPEED,
                'AvgSpeed': SPEED,
                'Devices': Devices,
                'AnalyzedData': AnalyzedData,
                'TotalPackets': len(Packets)
            })
            print("Sent " + str(len(temp_packets)) + " packets")
            print("Total packets: " + str(len(Packets)) + "\n")
            temp_packets = []
            for i in range(len(InstantaneousSPEED)):
                InstantaneousSPEED[i]['RBytes'] = 0
                InstantaneousSPEED[i]['SBytes'] = 0
            LOCK.release()
        except KeyboardInterrupt:
            # print("Keyboard  Interrupt")
            pass


@socket_.on('start_sniffing')
def start_sniffing(data):
    global thread, Continue
    if not Continue:
        Continue = True
        print("Starting Sniffing", data)
        if data['interface']:
            emit('sniffing', {'data': 'Connected! ayy', 'status': 'success'})
            dataGenerator(data['interface'])
        else:
            emit('sniffing', {'data': 'Interface not selected!', 'status': 'error'})
    else:
        emit('sniffing', {'data': 'Sniffing already started!', 'status': 'success'})


@socket_.on('stop_sniffing')
def stop_sniffing():
    print(time.time() - StartTime)
    global Continue
    Continue = False
    print("Stopping Thread")
    emit('stoped_sniffing', {'data': 'Stopped Sniffing', 'status': 'success'})


@socket_.on('setFilters')
def set_filters(data):
    global FILTERS, LOCK
    LOCK.acquire()
    FILTERS = data
    LOCK.release()
    emit('Filters', {'data': 'Filters set', 'status': 'success'})
    print("Filters: ", data)


@socket_.on('clearFilters')
def clear_filters():
    global FILTERS, LOCK
    LOCK.acquire()
    FILTERS = []
    LOCK.release()
    emit('Filters', {'data': 'Filters cleared', 'status': 'success'})
    print("Filters: ", FILTERS)


@socket_.on('get_devices')
def get_devices():
    global GetDevices, Continue
    if not Continue:
        emit('devices', {'data': 'Please start sniffing first', 'status': 'error'})
    else:
        GetDevices = True
        emit('devices', {'data': 'Done', 'status': 'success'})


@socket_.on('get_imported_data')
def get_imported_data():
    emit('imported_data', {'data': 'Done', 'status': 'success', 'Devices': Devices,
                           'InstantaneousSPEED': InstantaneousSPEED, 'AnalyzedData': AnalyzedData, 'AvgSpeed': SPEED,
                           'TotalPackets': len(Packets)})


@socket_.on('get_pagination_packets')
def get_pagination_packets():
    global PaginationPackets
    emit('pagination_packets', {'data': 'Done', 'status': 'success', 'PaginationPackets': PaginationPackets})


@app.route('/upload', methods=['POST'])
def upload_file():
    global Packets, temp_packets, StartTime, SPEED, Devices, LOCK, Continue, FILTERS, AnalyzedData, InstantaneousSPEED
    Packets = []
    temp_packets = []
    StartTime = None
    SPEED = []
    Devices = []
    LOCK = threading.Lock()
    Continue = False
    AnalyzedData = []
    InstantaneousSPEED = []
    end_time = 0
    try:
        file = request.files['file']
        if file:
            filename = 'temp.pcap'
            # save in current folder
            file.save(os.path.join(os.getcwd(), filename))
            # read pcap file
            Packets = rdpcap(filename)
            for i in range(0, len(Packets)):
                packet_json = Sniffer().create_packet_json(Packets[i])
                if packet_json["Frame_info"]["deviceType"] != "Broadcast":
                    extractDeviceFromPacket(packet_json)
                    getTheSpeedOfEachDevice(packet_json)
                extractPacketProtocols(packet_json)
                if not StartTime:
                    StartTime = float(packet_json["Frame_info"]["Arrival_time"])
                end_time = packet_json["Frame_info"]["Arrival_time"]
            for i in range(len(SPEED)):
                InstantaneousSPEED[i]["instantanouesRSpeed"] = 0
                InstantaneousSPEED[i]["instantanouesSSpeed"] = 0
                if time.time() - StartTime:
                    if StartTime:
                        SPEED[i]['avgRSpeed'] = float(SPEED[i]['RBytes'] / (end_time - StartTime))
                        SPEED[i]['avgSSpeed'] = float(SPEED[i]['SBytes'] / (end_time - StartTime))
                    else:
                        SPEED[i]['avgRSpeed'] = 0
                        SPEED[i]['avgSSpeed'] = 0
                else:
                    SPEED[i]['avgRSpeed'] = SPEED[i]['RBytes']
                    SPEED[i]['avgSSpeed'] = SPEED[i]['SBytes']
            # remove file
            os.remove(filename)

            return {'data': 'Done', 'status': 'success'}
        return {'data': 'Error', 'status': 'error'}
    except Exception as e:
        print(e)
        return {'data': str(e), 'status': 'error'}


@app.route('/download', methods=['POST'])
def download_file():
    global Packets
    try:
        fileName = json.loads(request.get_data())['file']
        if fileName:
            # create a folder of the created files
            if not os.path.exists('files'):
                os.mkdir('files')
            # remove all the files in the folder
            for file in os.listdir('files'):
                os.remove(os.path.join('files', file))
            # save the file

            fileName = 'files/' + fileName + '.pcap'
            wrpcap(fileName, Packets)
            return send_file(fileName, as_attachment=True)
        return {'data': 'Error', 'status': 'error'}
    except Exception as e:
        print(e)
        return {'data': str(e), 'status': 'error'}


@app.route('/getpackets', methods=['POST'])
def get_packets():
    global Packets, LOCK, PaginationPackets
    try:
        data = json.loads(request.get_data())
        page = data['page']
        size = data['size']
        LOCK.acquire()
        temp_packets = []
        upperLimit = (page + 1) * size
        iterator = 0
        if len(Packets) < (page) * size + upperLimit:
            upperLimit = len(Packets) - page * size
        while len(temp_packets) < upperLimit and page * size+iterator < len(Packets):
            packet_json = Sniffer().create_packet_json(Packets[page * size + iterator])
            iterator += 1
            if applyFilters(packet_json):
                temp_packets.append(packet_json)
        LOCK.release()
        PaginationPackets = temp_packets
        return {'data': '', 'status': 'success'}
    except Exception as e:
        print(e)
        return {'data': str(e), 'status': 'error'}
