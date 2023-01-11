from scapy.all import *
import psutil


def print_layers(packet):
    print("Device Type: %s" % get_device_type(packet))
    print(create_packet_json(packet))

def get_interfaces_json():
    interfaces = psutil.net_if_addrs()
    interfaces_json = []

    for interface in interfaces:
        interface_json = {}
        interface_json["name"] = interface
        interface_json["addresses"] = []

        for address in interfaces[interface]:
            address_json = {}
            address_json["family"] = address.family
            address_json["address"] = address.address
            address_json["netmask"] = address.netmask
            address_json["broadcast"] = address.broadcast
            address_json["ptp"] = address.ptp

            interface_json["addresses"].append(address_json)

        interfaces_json.append(interface_json)

    return interfaces_json

if __name__ == "__main__":
    # packet = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    # print(get_device_type(packet))
    #
    # # sniff the packets
    # sniff(prn=print_layers)

    # get the network interfaces
    for interface in get_interfaces_json():
        print(interface)

#     input the interface

    interface = input("Enter the interface: ")

    # sniff the packets
    sniff(prn=print_layers, iface=interface)



