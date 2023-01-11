from flask_restful import Resource, Api
import psutil

class Interfaces(Resource):
    def get(self):
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
