from flask_restful import Resource, request
from scapy.all import *

class Sniffer(Resource):
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
            packet_json["Frame_protocols"] = [ layer.name for layer in self.__get_packet_layers(packet) ]
        #     get the security protocols

        except:
            packet_json["Frame_protocols"] = ""
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
        packet_json["layers"] = []

        for layer in self.__get_packet_layers(packet):
            layer_json = {}
            layer_json["name"] = layer.name
            layer_json["fields"] = {}

            for field in layer.fields_desc:
                layer_json["fields"][field.name] = getattr(layer, field.name)

            packet_json["layers"].append(layer_json)
            packet_json["Frame_info"] = self.__get_frame_info_json(packet)

        return packet_json

    def start(self, interface):
        def print_layers(packet):
            print("Device Type: %s" % self.__get_device_type(packet))
            print(self.__create_packet_json(packet))

        # sniff the packets
        sniff(prn=print_layers, iface=interface)

    def post(self):
        interface = request.json["interface"]
        self.start(interface)

        return {"message": "Sniffer started"}, 200
