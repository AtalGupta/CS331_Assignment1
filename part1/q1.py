import os
from scapy.all import rdpcap
import matplotlib.pyplot as plt


pcap_path = os.path.expanduser('Assignment1/captured123.pcap')

# Load the PCAP file
packets = rdpcap(pcap_path)

# Extract packet sizes
packet_sizes = [len(p) for p in packets]

# Calculate metrics
total_packets = len(packet_sizes)
total_bytes = sum(packet_sizes)
min_size = min(packet_sizes)
max_size = max(packet_sizes)
avg_size = total_bytes / total_packets

# Print metrics
print(f"Total Packets: {total_packets}")
print(f"Total Data Transferred: {total_bytes} bytes")
print(f"Minimum Packet Size: {min_size} bytes")
print(f"Maximum Packet Size: {max_size} bytes")
print(f"Average Packet Size: {avg_size:.2f} bytes")

# Plot histogram of packet sizes
plt.hist(packet_sizes, bins=50, color='blue', edgecolor='black')
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Frequency")
plt.show()