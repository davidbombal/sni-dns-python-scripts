# IMPORTANT: This script was created used ChatGPT. Use at your own risk.

from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime

LOG_FILE = "dns_log.txt"

# Optional: domains you want highlighted
BLOCKLIST = [
    "adult",
    "porn",
    "gambling",
    "casino",
]

seen = set()

def process_packet(packet):
    if packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode("utf-8").rstrip(".")

            # Avoid duplicate spam
            now_minute = datetime.now().strftime("%Y-%m-%d %H:%M")
            unique_key = f"{now_minute}:{domain}"

            if unique_key in seen:
                return

            seen.add(unique_key)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            warning = ""
            for word in BLOCKLIST:
                if word.lower() in domain.lower():
                    warning = " [POTENTIALLY INAPPROPRIATE]"
                    break

            log_entry = f"[{timestamp}] {domain}{warning}"

            # Print to screen
            print(log_entry)

            # Save to file
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")

        except Exception as e:
            print(f"Error processing packet: {e}")

print("DNS monitor started...")
print(f"Logging to: {LOG_FILE}")
print("Press CTRL+C to stop.\n")

# Sniff DNS traffic (UDP port 53)
sniff(filter="udp port 53", prn=process_packet, store=False)

