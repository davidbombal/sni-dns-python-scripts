# IMPORTANT: This script was created used ChatGPT. Use at your own risk.

from scapy.all import sniff, TCP, Raw
from datetime import datetime

LOG_FILE = "sni_log.txt"

def extract_sni(payload):
    try:
        data = bytes(payload)

        # TLS Handshake check
        if len(data) < 5:
            return None

        # TLS Handshake record
        if data[0] != 0x16:
            return None

        pos = 43

        # Session ID
        session_id_length = data[pos]
        pos += 1 + session_id_length

        # Cipher Suites
        cipher_suites_length = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2 + cipher_suites_length

        # Compression Methods
        compression_methods_length = data[pos]
        pos += 1 + compression_methods_length

        # Extensions
        extensions_length = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2

        end = pos + extensions_length

        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos+2], 'big')
            ext_length = int.from_bytes(data[pos+2:pos+4], 'big')
            pos += 4

            # SNI Extension
            if ext_type == 0x0000:
                sni_data = data[pos:pos+ext_length]

                # Skip list length + name type
                server_name_length = int.from_bytes(sni_data[3:5], 'big')
                server_name = sni_data[5:5+server_name_length]

                return server_name.decode(errors="ignore")

            pos += ext_length

    except Exception:
        return None

    return None

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        sni = extract_sni(payload)

        if sni:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] {sni}"

            print(line)

            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")

print("Listening for TLS SNI traffic...")
sniff(filter="tcp port 443", prn=packet_callback, store=False)
