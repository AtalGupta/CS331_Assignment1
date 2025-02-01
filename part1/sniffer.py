from scapy.all import sniff, wrpcap

def packet_callback(packet):
    print(f"Captured packet: {packet.summary()}")

# Start sniffing packets
def start_sniffing(interface=None, output_file="captured.pcap"):
    print(f"Starting packet capture on interface: {interface}")
    packets = sniff(iface=interface, prn=packet_callback, count=0)  
    print(f"Capture stopped. Saving packets to {output_file}")
    wrpcap(output_file, packets)

if __name__ == "__main__":
    interface = "eth0" 
    output_file = "captured1.pcap"
    start_sniffing(interface=interface, output_file=output_file)