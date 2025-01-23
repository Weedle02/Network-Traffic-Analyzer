# Network-Traffic-Analyzer
A security monitoring system to detect malicious network activity using Python, Scapy, and the ELK Stack.

## Features

- Real-time traffic analysis
- Detection of port scanning & DDoS attempts
- JSON alert logging
- ELK Stack integration
- Kibana dashboards for visualization
- PCAP file analysis support

## Repository Structure
network-analyzer/
elk-config/ # ELK Stack configurations
network-analyzer/ # Python analyzer scripts
sample_pcaps/ # Example traffic captures
README.md

## Requirements

- Python 3.8+
- Scapy 2.4.5+
- ELK Stack 7.10+
- Root privileges (for live capture)

