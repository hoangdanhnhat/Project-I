from pyshark import * #must install tshark first with pip install tshark
import struct

file_path = "/home/ratatoui1e/Documents/projectI/pcap_files/send-new.pcapng"
cap = FileCapture(file_path, display_filter="icmp")

secret_text=""
id = 0
for packet in cap:
    try:
        if packet.ip.src == "192.168.1.3":
            id += 1
            data_time = packet.icmp.data_time
            lsb = bin(int(data_time.raw_value[8:], 16))[-1:]
            secret_text += lsb

    except AttributeError:
        continue

cap.close()
print(''.join(chr(int(secret_text[i:i+8], 2)) for i in range(0, len(secret_text), 8)))