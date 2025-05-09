# real-time receiver for 2 byte per packet sender!

import pyshark
import time
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Real-time ICMP traffic analyzer for extracting secret messages.")
parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets (e.g., eth0, wlan0)")
parser.add_argument("-o", "--output", required=False, default="result.txt", help="Output file to store extracted messages")
args = parser.parse_args()

# Configuration from arguments
interface = args.interface
output_file = args.output

# Initialize state variables
messages = []
state = "WAIT_START"
zero_count = 0
secret_text_hex = ""
expected_data_length = 0
data_bytes_collected = 0
length_check_buffer = []

def save_message_to_file(message):
    """Append a message to the output file with a timestamp."""
    with open(output_file, "a", encoding="utf-8") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def process_packet(packet):
    """Process each captured packet."""
    global state, zero_count, secret_text_hex, expected_data_length, data_bytes_collected, length_check_buffer, messages

    try:
        if packet.icmp.type == "8":  # ICMP Echo Request
            data_time = packet.icmp.data_time
            lsb = data_time.raw_value[16:20] #2 bytes

            if state == "WAIT_START":
                first_byte, second_byte = lsb[2:], lsb[:2]
                if f"{int(first_byte, 16) ** 2:02x}"[-2:] == second_byte:
                    zero_count += 1
                    if zero_count == 3:
                        state = "VERIFY_LENGTH"
                        length_check_buffer = []
                        return
                else:
                    zero_count = 0

            elif state == "VERIFY_LENGTH":
                length_check_buffer.append(lsb)
                if len(length_check_buffer) == 2:
                    if int(length_check_buffer[0][:2], 16) + int(length_check_buffer[0][2:], 16) \
                        == int(length_check_buffer[1][:2], 16) + int(length_check_buffer[1][2:], 16):
                        expected_data_length = int(length_check_buffer[0][:2], 16) + int(length_check_buffer[0][2:], 16)
                        state = "READ_DATA"
                        secret_text_hex = ""
                        data_bytes_collected = 0
                    else:
                        state = "WAIT_START"
                        zero_count = 0

            elif state == "READ_DATA":
                if data_bytes_collected < expected_data_length:
                    secret_text_hex += lsb[2:] + lsb[:2]
                    data_bytes_collected += 1
                if data_bytes_collected == expected_data_length:
                    try:
                        decoded_text = bytes.fromhex(secret_text_hex).decode("utf-8")
                        messages.append(decoded_text)
                        print(f"[NEW MESSAGE] {decoded_text}")
                        save_message_to_file(decoded_text)
                    except Exception as e:
                        error_msg = f"[Decode Error]: {e}"
                        messages.append(error_msg)
                        print(error_msg)
                        save_message_to_file(error_msg)
                    state = "WAIT_START"
                    zero_count = 0

    except AttributeError:
        pass

def main():
    print(f"Starting real-time ICMP capture on interface {interface}")
    print(f"Messages will be saved to {output_file}")
    
    # Initialize the output file (clear it or create it)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("Extracted ICMP Messages\n")
    
    # Set up live capture with ICMP filter
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="icmp")
    
    try:
        # Capture packets and process them in real-time
        capture.apply_on_packets(process_packet)
    except KeyboardInterrupt:
        print("\n[STOPPED] Capture interrupted by user.")
        print("[RESULT] Extracted Messages:")
        for i, msg in enumerate(messages, 1):
            print(f"{i}. {msg}")
    finally:
        capture.close()

if __name__ == "__main__":
    main()