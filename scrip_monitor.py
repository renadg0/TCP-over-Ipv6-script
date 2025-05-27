# Imports and logging setup
from scapy.all import sniff, IPv6, TCP, Raw, IPv6ExtHdrFragment, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop
import psutil
import logging
import sys
import time
from datetime import datetime
from collections import defaultdict
import csv

# Initialize logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ipv6_tcp_monitor.log', encoding='utf-8')
    ]
)

# Define monitor class to track TCP over IPv6 anomalies
class TCPIPv6AdvancedMonitor:
    # Initialize state tracking and logs
    def __init__(self):
        self.states = defaultdict(lambda: {'state': 'UNKNOWN', 'last_seen': datetime.now(), 'count': 0})
        self.fragment_data = defaultdict(list)
        self.fragment_counter = 0
        self.last_fragment_reset = time.time()
        self.logger = logging.getLogger(__name__)
        self.memory_log = []
        self.anomalies = []
        self.latency_log = []
        self.max_log_entries = 10000

    # Analyze individual packets for IPv6 and TCP anomalies
    def analyze_packet(self, packet):
        try:
            now = datetime.now()

            if IPv6 in packet:
                ip = packet[IPv6]
                extensions = []

                # Detect IPv6 extension headers
                if IPv6ExtHdrHopByHop in packet:
                    extensions.append('HBH')
                if IPv6ExtHdrRouting in packet:
                    rh = packet[IPv6ExtHdrRouting]
                    extensions.append(f'RH Type {rh.type}')
                    if rh.type == 0:
                        self.anomalies.append((now, 'Deprecated RH0 header detected', (ip.src, ip.dst)))
                if IPv6ExtHdrDestOpt in packet:
                    extensions.append('DOH')
                if extensions:
                    self.logger.info(f"IPv6 EHs Detected from {ip.src} to {ip.dst}: {extensions}")

                # Track fragmented packets
                if IPv6ExtHdrFragment in packet:
                    frag = packet[IPv6ExtHdrFragment]
                    frag_id = frag.id
                    offset = frag.offset
                    key = (ip.src, ip.dst, frag_id)
                    self.fragment_data[key].append((offset, len(packet)))
                    self.fragment_counter += 1
                    self.logger.debug(f"Fragmented packet: ID={frag_id}, Offset={offset}, M={frag.m}")

                    # Detect overlapping and non-sequential fragments
                    if len(self.fragment_data[key]) >= 2:
                        offsets = [o for o, _ in self.fragment_data[key]]
                        if len(offsets) != len(set(offsets)):
                            self.anomalies.append((now, f"Overlapping fragments from {key}", key))
                        if sorted(offsets) != list(range(min(offsets), max(offsets)+1)):
                            self.anomalies.append((now, f"Non-sequential fragments from {key}", key))

            if TCP in packet:
                tcp = packet[TCP]
                key = (ip.src, ip.dst, tcp.sport, tcp.dport)

                # Update TCP connection states
                self.states[key]['last_seen'] = now
                self.states[key]['count'] += 1

                # Detect RST floods and unknown states
                if tcp.flags & 0x04:
                    self.anomalies.append((now, 'RST flood candidate', key))

                if self.states[key]['state'] == 'UNKNOWN':
                    self.anomalies.append((now, 'Unknown TCP state', key))

                self.states[key]['state'] = str(tcp.flags)

                # Measure latency if payload present
                if Raw in packet:
                    payload = bytes(packet[Raw])
                    if payload:
                        latency = time.time() - packet.time
                        self.latency_log.append((now, latency))
                        self.logger.info(f"Latency: {latency:.6f} seconds")

            # Periodic fragment flood detection
            if time.time() - self.last_fragment_reset >= 60:
                if self.fragment_counter > 100:
                    self.anomalies.append((now, f'Fragmentation flood detected: {self.fragment_counter}', 'IPv6'))
                    self.logger.warning(f"High fragment count: {self.fragment_counter} in last minute")
                else:
                    self.logger.info(f"Fragments last minute: {self.fragment_counter}")
                self.fragment_counter = 0
                self.last_fragment_reset = time.time()

            # Log memory usage every second
            if len(self.memory_log) == 0 or (now - self.memory_log[-1][0]).total_seconds() >= 1:
                mem = psutil.virtual_memory().percent
                self.memory_log.append((now, mem))
                self.logger.info(f"Memory usage: {mem}%")

        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")

    # Report detected anomalies via logging
    def report_anomalies(self):
        for t, reason, key in self.anomalies:
            self.logger.warning(f"[{t}] Anomaly: {reason} in {key}")

    # Export logs to CSV files
    def export_logs(self):
        try:
            with open('memory_usage.csv', 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Timestamp', 'Memory Usage (%)'])
                writer.writerows(self.memory_log)

            with open('latency_log.csv', 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Timestamp', 'Latency (s)'])
                writer.writerows(self.latency_log)
        except Exception as e:
            self.logger.error(f"Error exporting logs: {e}")

# Main function to start the sniffing process
def main():
    monitor = TCPIPv6AdvancedMonitor()
    logging.info("Starting Advanced IPv6 TCP Anomaly Monitor...")

    try:
        sniff(filter="ip6", prn=monitor.analyze_packet, store=0)
    except KeyboardInterrupt:
        monitor.report_anomalies()
        monitor.export_logs()
        logging.info("Monitor stopped.")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

