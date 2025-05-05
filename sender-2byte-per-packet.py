from scapy.all import IP, ICMP, sr1
import time
import struct
import math
import argparse

parser = argparse.ArgumentParser(description="ICMP traffic stealth sender for secret messages.")
parser.add_argument("-m", "--message", required=True, help="Message that need to be sent!")
parser.add_argument("-d", "--destination", required=True, help="The ip address of the receiver machine.")
args = parser.parse_args()

def build_ping_packet(dst_ip, identifier, sequence_number, chunk):
    # Current time for timestamp
    now = time.time()
    seconds = int(now)
    microseconds = int((now - seconds) * 1_000_000)
    microseconds_hex = hex(microseconds)[2:-4] + chunk
    malicious_mircoseconds = int(microseconds_hex, 16)

    # Create timestamp (8 bytes) - seconds and microseconds
    timestamp = struct.pack('QQ', seconds, malicious_mircoseconds)

    # Create pattern to fill the payload (after timestamp)
    pattern = bytes(range(0x10, 0x10 + 40))  # 40 bytes: 0x10 to 0x37

    # Final payload: timestamp + pattern (total 48 bytes)
    payload = timestamp + pattern

    # Build full packet
    packet = IP(dst=dst_ip)/ICMP(id=identifier, seq=sequence_number)/payload

    return packet

if __name__ == "__main__":
    # Target IP address
    target = args.destination

    sleep_time = 0.1

    # Example ID and Sequence
    icmp_id = 3417
    icmp_seq = 0

    secretText = args.message
    secretText_hex = secretText.encode('utf-8').hex()
    secretText_hex =  secretText_hex + "0" * (len(secretText_hex) % 4)

    for i in range(3):
        pkt = build_ping_packet(target, icmp_id, icmp_seq, "0000")
        response = sr1(pkt, timeout = 2, verbose = 0)
        if response:
            print(f"Received response for icmp_seq {icmp_seq} from {response.src} - pattern bytes")
        else:
            print("No response received (timeout)")
        time.sleep(sleep_time)

    pkt = build_ping_packet(target, icmp_id, icmp_seq, f"00{math.ceil(len(secretText_hex)/4):02x}")
    response = sr1(pkt, timeout = 2, verbose = 0)
    if response:
        print(f"Received response for icmp_seq {icmp_seq} from {response.src} - length byte = {math.ceil(len(secretText_hex)/4):02x}")
    else:
        print("No response received (timeout)")
    time.sleep(sleep_time)
    
    response = sr1(pkt, timeout = 2, verbose = 0)
    if response:
        print(f"Received response for icmp_seq {icmp_seq} from {response.src} - length byte = {math.ceil(len(secretText_hex)/4):02x}")
    else:
        print("No response received (timeout)")
    time.sleep(1) #change to adjust transfer speed

    for i in range(0, len(secretText_hex) - 1, 4):
        chunk = secretText_hex[i:i+4] 
        # Build packet
        icmp_seq += 1   
        pkt = build_ping_packet(target, icmp_id, icmp_seq, chunk)
        # Send packet
        response = sr1(pkt, timeout = 2, verbose = 0)
        if response:
            print(f"Received response for icmp_seq {icmp_seq} from {response.src}")
        else:
            print("No response received (timeout)")
        time.sleep(sleep_time) #change to adjust transfer speed