from scapy.all import rdpcap

def count_login_attempts(packets, target_ip):
    login_attempts = 0
    for packet in packets:
        if packet.haslayer('IP') and packet['IP'].src == target_ip and packet.haslayer('TCP'):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode(errors='ignore')
                if "POST" in payload and "login" in payload.lower():
                    login_attempts += 1
    return login_attempts

def find_successful_login_credentials(packets, target_ip, success_indicator):
    for packet in packets:
        if packet.haslayer('IP') and packet['IP'].src == target_ip and packet.haslayer('TCP'):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode(errors='ignore')
                if "POST" in payload and "login" in payload.lower() and success_indicator in payload:
                    return payload  
    return None

def get_successful_login_port(packets, target_ip, success_indicator):
    for packet in packets:
        if packet.haslayer('IP') and packet['IP'].src == target_ip and packet.haslayer('TCP'):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode(errors='ignore')
                if "POST" in payload and "login" in payload.lower() and success_indicator in payload:
                    return packet['TCP'].sport 
    return None

def total_content_length_of_login_attempts(packets, target_ip):
    total_length = 0
    for packet in packets:
        if packet.haslayer('IP') and packet['IP'].src == target_ip and packet.haslayer('TCP'):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load.decode(errors='ignore')
                if "POST" in payload and "login" in payload.lower():
                    total_length += len(payload)  
    return total_length

if __name__ == "__main__":
    pcap_file = "../3.pcap"
    target_ip = "192.168.10.50"
    success_indicator = "securepassword"

    packets = rdpcap(pcap_file)

    # Q1: Count the number of login attempts
    attempts = count_login_attempts(packets, target_ip)
    print(f"Total login attempts made: {attempts}")

    # Q2: Find credentials in the successful login attempt
    credentials = find_successful_login_credentials(packets, target_ip, success_indicator)
    if credentials:
        print(f"Successful login attempt payload: {credentials}")
    else:
        print("No successful login attempt found.")

    # Q3: Get the client's source port number for the successful login attempt
    port = get_successful_login_port(packets, target_ip, success_indicator)
    if port:
        print(f"Client's source port for successful login attempt: {port}")
    else:
        print("No successful login attempt found.")

    # Q4: Calculate total content length of all login attempt payloads
    total_length = total_content_length_of_login_attempts(packets, target_ip)
    print(f"Total content length of all login attempt payloads: {total_length}")