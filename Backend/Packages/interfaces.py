from flask_restful import Resource, Api
import psutil

class Interfaces(Resource):
    def get(self):
        interfaces = psutil.net_if_addrs()
        interfaces_json = []

        for interface in interfaces:
            interface_json = {}
            interface_json["Name"] = interface
            try:
                interface_json["Address"] = interfaces[interface][0].address
            except:
                interface_json["Address"] = ''
            try:
                interface_json["MacAddress"] = interfaces[interface][2].address
            except:
                interface_json["MacAddress"] = ''
            try:
                interface_json["IP"] = interfaces[interface][1].address
            except:
                interface_json["IP"] = ''

            interfaces_json.append(interface_json)

        return interfaces_json
