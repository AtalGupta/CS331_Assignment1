from scapy.all import rdpcap
import os

# Load the PCAP file
pcap_path = os.path.expanduser('Assignment1/captured123.pcap')
packets = rdpcap(pcap_path)

# Create a set to store unique source-destination pairs
unique_pairs = set()

for packet in packets:
    if 'IP' in packet and 'TCP' in packet: 
        src_ip = packet['IP'].src 
        src_port = packet['TCP'].sport  
        dst_ip = packet['IP'].dst  
        dst_port = packet['TCP'].dport 
        
        pair = (src_ip, src_port, dst_ip, dst_port)
        unique_pairs.add(pair)

# Save all pairs to a text file and include the count at the end
output_path = "unique_pairs.txt"
with open(output_path, "w") as file:
    for pair in unique_pairs:
        file.write(f"{pair[0]}:{pair[1]} -> {pair[2]}:{pair[3]}\n")
    
    file.write(f"\nTotal Unique Source-Destination Pairs: {len(unique_pairs)}\n")

print(f"Total Unique Source-Destination Pairs saved to {output_path}")
