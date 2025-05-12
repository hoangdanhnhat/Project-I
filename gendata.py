import random
import string
import struct
from datetime import datetime, timedelta
import pandas as pd


def random_datetime(start_year=2000, end_year=2025):
    """
    Trả về một datetime ngẫu nhiên giữa start_year và end_year.
    """
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31, 23, 59, 59)
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))


def generate_secret_with_time(prefix=""):
    """
    Sinh secret string với prefix và timestamp giả.
    Trả về (secret, fake_time).
    """
    length = random.randint(5, 20)
    secret = f"{prefix}_{''.join(random.choices(string.ascii_letters + string.digits, k=length))}"
    fake_time = random_datetime()
    return secret, fake_time


def build_timestamp_hex(seconds, micro):
    """
    Chuyển seconds và micro (cả 64-bit) thành chuỗi 16 byte hex (little-endian).
    """
    ts = struct.pack('QQ', seconds, micro)
    return ' '.join(f'{b:02x}' for b in ts)


def generate_normal_timestamp(fake_time):
    """
    Tạo timestamp normal:
    - Giây = fake_time.timestamp()
    - Micro:
      - byte 1-2 (index 0-1) random 0-255
      - byte 3 (index 2) random 0x00-0x0f
      - byte cao index 3-7 = 0x00
    """
    seconds = int(fake_time.timestamp())
    micro_bytes = bytearray(8)
    micro_bytes[0] = random.randint(0, 0xff)
    micro_bytes[1] = random.randint(0, 0xff)
    micro_bytes[2] = random.randint(0x00, 0x0f)
    # bytes 3-7 đã là 0
    micro = struct.unpack('Q', micro_bytes)[0]
    return build_timestamp_hex(seconds, micro)


def generate_covert_timestamp(fake_time, data_chunk):
    """
    Tạo timestamp covert chèn 2 byte:
    - Giây = fake_time.timestamp()
    - Micro:
      - byte 1-2 (index 0-1) chứa data_chunk (1-2 ký tự UTF-8), pad 0 nếu thiếu
      - byte 3 (index 2) random 0x00-0x0f
      - byte cao index 3-7 = 0x00
    """
    seconds = int(fake_time.timestamp())
    micro_bytes = bytearray(8)
    # embed 2-byte chunk
    chunk_bytes = data_chunk.encode('utf-8')
    for i in range(min(2, len(chunk_bytes))):
        micro_bytes[i] = chunk_bytes[i]
    micro_bytes[2] = random.randint(0x00, 0x0f)
    # bytes 3-7 = 0
    micro = struct.unpack('Q', micro_bytes)[0]
    return build_timestamp_hex(seconds, micro)


def generate_covert1_timestamp(fake_time, data_byte):
    """
    Tạo timestamp covert chèn 1 byte thấp nhất:
    - Giây = fake_time.timestamp()
    - Micro:
      - byte 1 (index 0) chứa data_byte (1 ký tự UTF-8)
      - byte 2 (index 1) random 0-255
      - byte 3 (index 2) random 0x00-0x0f
      - byte cao index 3-7 = 0x00
    """
    seconds = int(fake_time.timestamp())
    micro_bytes = bytearray(8)
    # embed single byte
    b = data_byte.encode('utf-8')[0]
    micro_bytes[0] = b
    micro_bytes[1] = random.randint(0, 0xff)
    micro_bytes[2] = random.randint(0x00, 0x0f)
    # bytes 3-7 = 0
    micro = struct.unpack('Q', micro_bytes)[0]
    return build_timestamp_hex(seconds, micro)

def generate_covert1bit_timestamp(fake_time, bit):
    """
    Tạo timestamp covert chèn 1 bit (0 hoặc 1) vào bit cuối của byte cuối cùng (index 7) trong microsecond.
    """
    assert bit in (0, 1), "bit must be 0 or 1"
    seconds = int(fake_time.timestamp())
    micro_bytes = bytearray(random.getrandbits(8) for _ in range(8))
    micro_bytes[7] = (micro_bytes[7] & 0b11111110) | bit
    micro = struct.unpack('Q', micro_bytes)[0]
    return build_timestamp_hex(seconds, micro)


def encode_string_to_bits(s):
    """
    Mã hóa chuỗi UTF-8 thành list các bit (0/1), mỗi ký tự -> 8 bit.
    """
    return [int(b) for c in s.encode('utf-8') for b in f'{c:08b}']



def main():
    num_normal = 2500
    num_covert = 1250
    num_covert1 = 1250
    prefixes = [""]

    data = []
    blank_ts = ' '.join(['00'] * 16)

    # Normal sequences
    normal_times = [random_datetime() for _ in range(num_normal)]
    for fake_time in normal_times:
        seq = []
        packets = random.randint(5, 10)
        for _ in range(packets):
            ts = generate_normal_timestamp(fake_time)
            seq.append({'timestamp': ts, 'label': 0})
            fake_time += timedelta(seconds=random.randint(1, 2))
        seq = seq[-5:] if len(seq) > 5 else seq + [{'timestamp': blank_ts, 'label': 0}] * (5 - len(seq))
        data.extend(seq)

    # Covert sequences (2-byte)
    covert_entries_2bytes = [generate_secret_with_time(prefixes[0]) for _ in range(num_covert)]
    for secret, fake_time in covert_entries_2bytes:
        seq = []
        # marker
        seq.append({'timestamp': generate_covert_timestamp(fake_time, "\x00\x00"), 'label': 1})
        fake_time += timedelta(seconds=random.randint(1, 5))
        # length
        length_chunk = chr(len(secret)) + "\x00"
        seq.append({'timestamp': generate_covert_timestamp(fake_time, length_chunk), 'label': 1})
        for i in range(0, len(secret), 2):
            chunk = secret[i:i+2]
            seq.append({'timestamp': generate_covert_timestamp(fake_time, chunk), 'label': 1})
            fake_time += timedelta(seconds=random.randint(1, 2))
        seq = seq[-5:] if len(seq) > 5 else seq + [{'timestamp': blank_ts, 'label': 1}] * (5 - len(seq))
        data.extend(seq)

    # Covert sequences (1-byte)
    covert_entries_1byte = [generate_secret_with_time(prefixes[0]) for _ in range(num_covert1)]
    for secret, fake_time in covert_entries_1byte:
        seq1 = []
        for ch in secret:
            seq1.append({'timestamp': generate_covert1_timestamp(fake_time, ch), 'label': 1})
            fake_time += timedelta(seconds=random.randint(1, 2))
        seq1 = seq1[-5:] if len(seq1) > 5 else seq1 + [{'timestamp': blank_ts, 'label': 1}] * (5 - len(seq1))
        data.extend(seq1)

    # Covert sequences (1-bit)
    covert_entries_1bit = [generate_secret_with_time(prefixes[0]) for _ in range(num_covert1)]
    for secret, fake_time in covert_entries_1bit:
        bits = encode_string_to_bits(secret)
        seq2 = []
        for bit in bits:
            seq2.append({'timestamp': generate_covert1bit_timestamp(fake_time, bit), 'label': 1})
            fake_time += timedelta(seconds=random.randint(1, 2))
        seq2 = seq2[-5:] if len(seq2) > 5 else seq2 + [{'timestamp': blank_ts, 'label': 1}] * (5 - len(seq2))
        data.extend(seq2)


    # Xuất CSV
    df = pd.DataFrame(data)
    df.to_csv('test.csv', index=False)
    print("Đã tạo file test.csv thành công!")


if __name__ == '__main__':
    main()
