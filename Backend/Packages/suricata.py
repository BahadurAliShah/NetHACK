import json
import subprocess
import os
import shutil
from scapy.all import *

SURICATACONFIG = "C:\\Program Files\\Suricata\\suricata.yaml"

def analyze(packets):
    # create the pcap file

    # Run suricata on the file
    alerts = []
    directory = "suricata"
    current_directory = os.getcwd()
    print(current_directory)
    try:
        os.mkdir(current_directory + "\\" + directory)
    except:
        pass

    # write the packets to a pcap file
    file_path = current_directory + "\\" + directory + "\\packets.pcap"
    wrpcap(file_path, packets)

    subprocess.run(
        ["suricata", "-r", file_path, "-l", current_directory + "\\" + directory, "-c",
         SURICATACONFIG])

    logs = current_directory + "\\" + directory + "\\fast.log"

    with open(logs, "r") as f:
        for line in f:
            alerts.append(line)

    shutil.rmtree(directory)

    return alerts


if __name__ == "__main__":
    alerts = analyze("C:\\Users\\badar\\OneDrive\\Desktop\\Testing (1).pcap")
    print(alerts)
