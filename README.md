# README

## Install tshark

- Fedora

```
sudo dnf install wireshark-cli -y
```

## Install dependencies with

```python
pip install -r requirements.txt
```

## How to use

### Start the real-time receiver with

```python
sudo python3 realtime-receiver.py -i {your_network_interface} -o {output_file_name}
```

### Send the message to the real-time receiver

```python
sudo python3 sender-2byte-per-packet.py -d {receiver_ip_address} -t {delay time between packets} -m "{your_message_here}"
```
