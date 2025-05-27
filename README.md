This Python script monitors IPv6 TCP network traffic in real-time to detect anomalies and potential attacks. It analyzes IPv6 extension headers, fragmented packets, and TCP states, while also logging memory usage of the system during monitoring. The tool features advanced anomaly detection, detailed logging, and exports data for further analysis.

Key Features:
1. Real-time sniffing and analysis of IPv6 and TCP packets
2. Detection of abnormal fragmented packet patterns (e.g., overlapping, non-sequential fragments)
3. Monitoring of TCP connection states and detection of suspicious behaviors (e.g., RST floods)
4. Analysis of IPv6 extension headers including Routing Header (RH0), Hop-by-Hop, and Fragmentation headers
5. Integration with psutil for system memory usage monitoring during runtime
6. Detailed logging and anomaly classification
7. Export of logs in CSV format for external analysis
