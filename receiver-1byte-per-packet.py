from pyshark import * #must install tshark first with pip install tshark

file_path = "/home/ratatoui1e/Documents/projectI/pcap_files/helloworld-1bpp.pcapng"
cap = FileCapture(file_path, display_filter="icmp")

secret_text_hex = ""

for packet in cap:
    try:
        if packet.ip.src == "172.20.10.3": # change this to match the sender ip address
            data_time = packet.icmp.data_time
            least_significant_byte = data_time.raw_value[-2:]
            secret_text_hex += least_significant_byte

    except AttributeError:
        continue

cap.close()
print(bytes.fromhex(secret_text_hex).decode('utf-8'))