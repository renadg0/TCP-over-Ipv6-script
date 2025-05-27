TCP over IPv6 Anomaly Detection Script
This Python script provides real-time monitoring and analysis of IPv6 TCP network traffic to detect anomalies and potential security threats. It inspects IPv6 extension headers, fragmented packets, and TCP connection states to identify suspicious activities such as overlapping or non-sequential fragmented packets, RST floods, and usage of deprecated headers like Routing Header Type 0 (RH0).
In addition to network traffic analysis, the script integrates with the psutil library to monitor system memory usage during runtime, correlating resource consumption with network events. The tool logs detailed events and anomalies, classifies detected irregularities, and exports logs in CSV format for further offline analysis or visualization.


Key Features
1. Real-time packet sniffing and analysis for IPv6 and TCP traffic using Scapy.
2. Detection of abnormal fragmented packet patterns, including overlapping and non-sequential fragments.
3. Monitoring TCP connection states to detect suspicious behaviors such as RST flood attacks.
4. Analysis of IPv6 extension headers, including Routing Header (RH0), Hop-by-Hop Options, Destination Options, and Fragmentation headers.
5. Integration with psutil for continuous monitoring of system memory usage.
6. Advanced logging system that captures detailed information on network events and anomalies.
7. Export of logs to CSV files for easy review and further analysis with external tools.


Usage
Run the script with Python 3.x. It requires root/administrator privileges to capture network packets. Logs will be saved to files, and summary reports will be shown on termination (e.g., Ctrl+C).
sudo python3 scrip_monitor.py


Dependencies
1. Scapy
2. psutil
Install dependencies with:
pip install scapy psutil


Future Improvements
1. Incorporate known IPv6 attack signatures from databases like NVD.
2. Implement machine learning techniques for enhanced anomaly detection and reduced false positives.

