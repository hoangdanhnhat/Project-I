from pyshark import *

file_path = "/home/ratatoui1e/Documents/projectI/pcap_files/apr24.pcapng"
cap = FileCapture(file_path, display_filter="icmp")

messages = []
state = "WAIT_START"
zero_count = 0
secret_text_hex = ""
expected_data_length = 0
data_bytes_collected = 0
length_check_buffer = []

for packet in cap:
    try:
        if packet.ip.src == "127.0.0.1" and packet.icmp.type == "8":
            data_time = packet.icmp.data_time
            lsb = data_time.raw_value[-2:]

            if state == "WAIT_START":
                if lsb == "00":
                    zero_count += 1
                    if zero_count == 3:
                        state = "VERIFY_LENGTH"
                        length_check_buffer = []
                        continue  # skip this third '00'
                else:
                    zero_count = 0

            elif state == "VERIFY_LENGTH":
                length_check_buffer.append(lsb)
                if len(length_check_buffer) == 2:
                    if length_check_buffer[0] == length_check_buffer[1]:
                        expected_data_length = int(length_check_buffer[0], 16)
                        state = "READ_DATA"
                        secret_text_hex = ""
                        data_bytes_collected = 0
                    else:
                        # Not a valid message, go back to waiting
                        state = "WAIT_START"
                        zero_count = 0

            elif state == "READ_DATA":
                if data_bytes_collected < expected_data_length:
                    secret_text_hex += lsb
                    data_bytes_collected += 1
                if data_bytes_collected == expected_data_length:
                    try:
                        decoded_text = bytes.fromhex(secret_text_hex).decode("utf-8")
                        messages.append(decoded_text)
                    except Exception as e:
                        messages.append(f"[Decode Error]: {e}")
                    state = "WAIT_START"
                    zero_count = 0

    except AttributeError:
        continue

cap.close()

# Handle case where file ends in middle of a message
if state == "READ_DATA" and data_bytes_collected < expected_data_length:
    messages.append(f"[Incomplete Message] Expected {expected_data_length} bytes, got {data_bytes_collected}")

# Output
print("[RESULT] Extracted Messages:")
for i, msg in enumerate(messages, 1):
    print(f"{i}. {msg}")
