from pyshark import * #must install tshark first with pip install tshark
import struct

file_path = "/home/ratatoui1e/Documents/projectI/pcap_files/send-new.pcapng"
cap = FileCapture(file_path, display_filter="icmp")

secret_text_bin=""

for packet in cap:
    try:
        if packet.ip.src == "192.168.1.3": # change this to match the sender ip address
            data_time = packet.icmp.data_time
            lsb = bin(int(data_time.raw_value[8:], 16))[-1:]
            secret_text_bin += lsb

    except AttributeError:
        continue

cap.close()
print(''.join(chr(int(secret_text_bin[i:i+8], 2)) for i in range(0, len(secret_text_bin), 8)))
