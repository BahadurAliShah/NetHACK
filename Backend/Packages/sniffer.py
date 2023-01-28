from scapy.all import *
from app import socket_
import threading
import json
from flask_socketio import emit

temp_packets = []
Packets = []
Devices = []
IPs = []
Continue = False
LOCK = threading.Lock()
DELAY = 0.5

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
            packet_json["Arrival_time"] = packet.time
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
            packet_json["Frame_protocols"] = ["Frame_info", ]
            temp_layers = [layer.name for layer in self.__get_packet_layers(packet) ]
            new_layers = []
            for layer in temp_layers:
                counter = 1
                if temp_layers.count(layer) > 1:
                    for i in new_layers:
                        try:
                            if int(i.split("_")[-1]):
                                counter = int(i.split("_")[-1]) + 1
                        except:
                            pass
                    new_layers.append(layer + "_" + str(counter))
                else:
                    new_layers.append(layer)
            packet_json["Frame_protocols"].extend(new_layers)
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


        return packet_json


    def __create_packet_json(self, packet):
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
        def print_layers(packet):
            global temp_packets, Packets, Continue, Devices, LOCK
            # print(self.__create_packet_json(packet))

            packet_json = self.__create_packet_json(packet)
            if packet_json["Frame_info"]["deviceType"] == "Unicast":
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


                    if packet_json["IP"]["src"] not in IPs:
                        IPs.append(packet_json["IP"]["src"])
                    if packet_json["IP"]["dst"] not in IPs:
                        IPs.append(packet_json["IP"]["dst"])
                    if not deviceAlreadyExists:
                        Devices.append(device)
                except:
                    pass
            LOCK.acquire()
            temp_packets.append(packet_json)
            Packets.append(packet_json)
            # print(len(temp_packets))
            LOCK.release()
            print(IPs)
            print(Devices)

        def stopFilter(packet):
            global Continue
            return not Continue

        sniff(prn=print_layers, iface=interface, stop_filter=stopFilter, store=0, promisc=True)

    # def getDevices(self):
    #     global Packets



def dataGenerator(interface):
    global Continue
    print("Initialising")
    threading.Thread(target=Sniffer().start, args=(interface,)).start()
    try:
        while Continue:
            global temp_packets, Packets, LOCK
            while len(temp_packets) == 0 and Continue:
                socket_.sleep(DELAY)
            LOCK.acquire()
            socket_.emit('packet', {'data': json.dumps(temp_packets)})
            print("Sent " + str(len(temp_packets)) + " packets")
            print("Total packets: " + str(len(Packets)) + "\n")
            temp_packets = []
            LOCK.release()
    except KeyboardInterrupt:
        print("Keyboard  Interrupt")




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
    global Continue
    Continue = False
    print("Stopping Thread")
