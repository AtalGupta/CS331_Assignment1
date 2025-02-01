from scapy.all import rdpcap
import os
from collections import defaultdict


pcap_path = os.path.expanduser('Assignment1/captured123.pcap')
packets = rdpcap(pcap_path)

src_flows = defaultdict(int)  # Key: Source IP, Value: Total flows
dst_flows = defaultdict(int)  # Key: Destination IP, Value: Total flows
data_transferred = defaultdict(int)  # Key: (src_ip, dst_ip), Value: Total bytes transferred

# Iterate through each packet
for packet in packets:
    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1
        data_transferred[(src_ip, dst_ip)] += len(packet)

output_lines = []

output_lines.append("Source Flows (IP: Total Flows):")
for ip, flows in src_flows.items():
    output_lines.append(f"{ip}: {flows}")

output_lines.append("\nDestination Flows (IP: Total Flows):")
for ip, flows in dst_flows.items():
    output_lines.append(f"{ip}: {flows}")

# source-destination pair with the most data transferred
max_data_pair = max(data_transferred, key=data_transferred.get)
max_bytes = data_transferred[max_data_pair]

# max data transfer information 
output_lines.append("\nSource-Destination Pair with Most Data Transferred:")
output_lines.append(f"Source: {max_data_pair[0]} -> Destination: {max_data_pair[1]}")
output_lines.append(f"Total Bytes Transferred: {max_bytes}")

# Save output
output_file_path = os.path.expanduser('Assignment1/q3_output.txt')
with open(output_file_path, 'w') as f:
    f.write("\n".join(output_lines))

# Print output
print(f"Output saved to {output_file_path}")
print(f"Source-Destination Pair with Most Data Transferred: {max_data_pair[0]} -> {max_data_pair[1]} ({max_bytes} bytes)")