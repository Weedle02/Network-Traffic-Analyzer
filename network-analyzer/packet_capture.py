#!/usr/bin/env python3
import argparse
from collections import defaultdict
from datetime import datetime
import json
from scapy.all import sniff, IP, TCP
from scapy.layers.inet import ICMP, UDP


class AlertLogger:
    """Handles logging security alerts to a JSON file"""
    def __init__(self, log_file="alerts.json"):
        self.log_file = log_file

    def log_alert(self, alert_data):
        """Append alert to log file in JSON format"""
        with open(self.log_file, "a") as f:
            json.dump(alert_data, f)
            f.write("\n")


class TrafficAnalyzer:
    """Analyzes network traffic for suspicious patterns"""
    def __init__(self, syn_threshold=20, ddos_threshold=1000):
        self.syn_threshold = syn_threshold
        self.ddos_threshold = ddos_threshold
        
        # Track SYN packets per source IP
        self.syn_scan_tracker = defaultdict(set)
        
        # Track traffic volume per destination IP
        self.ddos_tracker = defaultdict(int)

    def process_packet(self, packet):
        """Process individual network packets"""
        if IP in packet:
            ip_pkt = packet[IP]
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # DDoS tracking (all IP traffic)
            self.ddos_tracker[dst_ip] += 1

            # SYN scan detection (TCP only)
            if TCP in packet:
                tcp_pkt = packet[TCP]
                if tcp_pkt.flags == 'S':  # SYN flag set without ACK
                    self.syn_scan_tracker[src_ip].add(tcp_pkt.dport)

    def periodic_check(self, logger):
        """Check for threshold breaches and generate alerts"""
        current_time = datetime.now().isoformat()

        # Check for SYN scans
        for src_ip, ports in self.syn_scan_tracker.items():
            if len(ports) >= self.syn_threshold:
                alert = {
                    "timestamp": current_time,
                    "alert_type": "Port Scanning",
                    "source_ip": src_ip,
                    "target_ports": len(ports),
                    "message": f"SYN scan detected from {src_ip} scanning {len(ports)} ports"
                }
                logger.log_alert(alert)

        # Check for potential DDoS
        for dst_ip, count in self.ddos_tracker.items():
            if count >= self.ddos_threshold:
                alert = {
                    "timestamp": current_time,
                    "alert_type": "DDoS Suspicion",
                    "target_ip": dst_ip,
                    "packet_count": count,
                    "message": f"Potential DDoS on {dst_ip} - {count} packets received"
                }
                logger.log_alert(alert)

    def reset_trackers(self):
        """Reset analysis counters"""
        self.syn_scan_tracker.clear()
        self.ddos_tracker.clear()


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", default="eth0", 
                       help="Network interface to monitor")
    parser.add_argument("-s", "--syn-threshold", type=int, default=20,
                       help="SYN scan alert threshold (unique ports)")
    parser.add_argument("-d", "--ddos-threshold", type=int, default=1000,
                       help="DDoS detection threshold (packets/interval)")
    parser.add_argument("-l", "--log-file", default="alerts.json",
                       help="Alert output file")
    parser.add_argument("-t", "--interval", type=int, default=30,
                       help="Analysis interval in seconds")
    parser.add_argument("-p", "--pcap", help="PCAP file for offline analysis")
    args = parser.parse_args()

    logger = AlertLogger(args.log_file)
    analyzer = TrafficAnalyzer(syn_threshold=args.syn_threshold,
                              ddos_threshold=args.ddos_threshold)

    if args.pcap:
        print(f"Analyzing PCAP file: {args.pcap}")
        sniff(offline=args.pcap, prn=analyzer.process_packet, store=False)
        analyzer.periodic_check(logger)
    else:
        print(f"Monitoring interface {args.interface}...")
        try:
            while True:
                sniff(iface=args.interface,
                     prn=analyzer.process_packet,
                     timeout=args.interval,
                     store=False)
                analyzer.periodic_check(logger)
                analyzer.reset_trackers()
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")


if __name__ == "__main__":
    main()
