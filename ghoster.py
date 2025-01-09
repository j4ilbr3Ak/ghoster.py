import os
import time
import random
import re
import socket
import requests
from colorama import Fore, init
from cryptography.fernet import Fernet
from threading import Thread
from scapy.all import *

# Initialize colorama
init(autoreset=True)

# Function to display text in random colors
def random_color(text):
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    return random.choice(colors) + text + Fore.RESET

# Function to restart Tor service
def restart_tor():
    os.system("sudo systemctl restart tor")
    time.sleep(10)  # Give Tor time to restart

# Function to fetch current IP using Tor
def get_current_ip():
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://localhost:9050',
        'https': 'socks5h://localhost:9050'
    }
    try:
        r = session.get('http://httpbin.org/ip')
        return r.json()['origin']
    except requests.RequestException as e:
        print(random_color(f"Error fetching IP: {e}"))
        return None

# Function to rotate IP periodically
def ghoster():
    restart_tor()
    ip = get_current_ip()
    if ip:
        print(random_color(f"Your current IP is: {ip}"))

    while True:
        restart_tor()
        ip = get_current_ip()
        if ip:
            print(random_color(f"Your new IP is: {ip}"))
        print(random_color("Rotating IP address"))
        time.sleep(30)

def port_scan(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Set timeout for connection attempt
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(random_color(f"Port {port} is open on {target_ip}"))
        sock.close()
    except Exception as e:
        print(random_color(f"Error scanning port {port}: {e}"))

def vulnerability_scanner(target_ip):
    print(random_color(f"Scanning ports on {target_ip}..."))
    for port in range(1, 1001):  # Scan ports 1 to 1000
        thread = Thread(target=port_scan, args=(target_ip, port))
        thread.start()

def scan_network():
    target_ip = input("Enter the target IP address: ")
    vulnerability_scanner(target_ip)

def firewall_block_all():
    os.system("iptables --policy INPUT DROP")
    os.system("iptables --policy FORWARD DROP")
    os.system("iptables --policy OUTPUT DROP")

def firewall_accept_all():
    os.system("iptables --policy INPUT ACCEPT")
    os.system("iptables --policy FORWARD ACCEPT")
    os.system("iptables --policy OUTPUT ACCEPT")

def add_firewall_rule(direction, protocol, port, action):
    os.system(f"iptables -A {direction.upper()} -p {protocol} --dport {port} -j {action.upper()}")

def remove_firewall_rule(rule_num):
    os.system(f"iptables -D INPUT {rule_num}")
    os.system(f"iptables -D FORWARD {rule_num}")
    os.system(f"iptables -D OUTPUT {rule_num}")

def list_firewall_rules():
    os.system("iptables -L --line-numbers")

def firewall_menu():
    while True:
        menu = """
        1: Block all packets
        2: Accept all packets
        3: Add firewall rule
        4: Remove firewall rule
        5: List firewall rules
        6: Back to main menu
        """
        print(random_color(menu))
        choice = input("Enter your choice: ")
        
        if choice == "1":
            print(random_color("Blocking all packets"))
            firewall_block_all()
        elif choice == "2":
            print(random_color("Accepting all packets"))
            firewall_accept_all()
        elif choice == "3":
            direction = input("Enter direction (INPUT, OUTPUT, FORWARD): ").upper()
            protocol = input("Enter protocol (tcp, udp, icmp): ").lower()
            port = input("Enter port number: ")
            action = input("Enter action (ACCEPT, DROP): ").upper()
            add_firewall_rule(direction, protocol, port, action)
            print(random_color(f"Rule added: {direction} {protocol} {port} {action}"))
        elif choice == "4":
            rule_num = input("Enter rule number to remove: ")
            remove_firewall_rule(rule_num)
            print(random_color(f"Rule {rule_num} removed"))
        elif choice == "5":
            list_firewall_rules()
        elif choice == "6":
            break
        else:
            print(random_color("Invalid choice, please try again."))

def change_mac(interface, new_mac):
    print(random_color(f"Changing MAC address for {interface} to {new_mac}"))
    os.system(f"ifconfig {interface} down")
    os.system(f"ifconfig {interface} hw ether {new_mac}")
    os.system(f"ifconfig {interface} up")
    print(random_color(f"MAC address changed for {interface} to {new_mac}"))

def get_current_mac(interface):
    result = os.popen(f"ifconfig {interface}").read()
    mac_address = re.search(r"(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", result).group(0)
    return mac_address

def mac_menu():
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")
    current_mac = get_current_mac(interface)
    print(random_color(f"Current MAC address for {interface}: {current_mac}"))
    new_mac = input("Enter the new MAC address: ")
    change_mac(interface, new_mac)

def generate_key():
    return Fernet.generate_key()

def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        return key_file.read()

def save_key(key, key_path):
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    print(random_color(f"File {file_path} encrypted successfully."))

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
    print(random_color(f"File {file_path} decrypted successfully."))

def encryption_menu():
    key_path = input("Enter the path to save/load the key (e.g., mykey.key): ")
    if os.path.exists(key_path):
        key = load_key(key_path)
        print(random_color("Key loaded successfully."))
    else:
        key = generate_key()
        save_key(key, key_path)
        print(random_color(f"Key generated and saved to {key_path}."))

    while True:
        menu = """
        1: Encrypt a file
        2: Decrypt a file
        3: Back to main menu
        """
        print(random_color(menu))
        choice = input("Enter your choice: ")

        if choice == "1":
            file_path = input("Enter the file path to encrypt: ")
            encrypt_file(file_path, key)
        elif choice == "2":
            file_path = input("Enter the file path to decrypt: ")
            decrypt_file(file_path, key)
        elif choice == "3":
            break
        else:
            print(random_color("Invalid choice, please try again."))

def honeypot(port=9999):
    honeypot_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    honeypot_socket.bind(("0.0.0.0", port))
    honeypot_socket.listen(5)
    print(random_color(f"Honeypot running on port {port}"))

    while True:
        client_socket, addr = honeypot_socket.accept()
        print(random_color(f"Honeypot alert! Connection attempt from {addr}"))
        client_socket.close()

def network_monitor():
    print(random_color("Starting network monitoring..."))
    sniff(filter="", prn=packet_callback, store=0)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(random_color(f"Incoming packet from {src_ip} to {dst_ip}"))

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(random_color(f"  TCP packet: Source Port {src_port}, Destination Port {dst_port}"))

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(random_color(f"  UDP packet: Source Port {src_port}, Destination Port {dst_port}"))

        if ICMP in packet:
            print(random_color("  ICMP packet"))

        if DNS in packet:
            print(random_color("  DNS packet"))

def intrusion_detection():
    print(random_color("Starting intrusion detection system..."))
    while True:
        result = subprocess.run(['journalctl', '-u', 'sshd', '-n', '1'], capture_output=True, text=True)
        if "Failed password" in result.stdout:
            print(random_color("Potential SSH brute force attempt detected!"))

def main_menu():
    # Start honeypot and intrusion detection in separate threads
    honeypot_thread = Thread(target=honeypot)
    honeypot_thread.daemon = True
    honeypot_thread.start()

    intrusion_detection_thread = Thread(target=intrusion_detection)
    intrusion_detection_thread.daemon = True
    intrusion_detection_thread.start()

    while True:
        menu = """
        1: Change IP address
        2: Firewall
        3: Scan network
        4: Change MAC address
        5: Encrypt files
        6: Network Monitor
        7: Exit
        """
        print(random_color(menu))
        choice = input("Enter what tool to use: ")

        if choice == "1":
            ghoster()
        elif choice == "2":
            firewall_menu()
        elif choice == "3":
            scan_network()
        elif choice == "4":
            mac_menu()
        elif choice == "5":
            encryption_menu()
        elif choice == "6":
            network_monitor()
        elif choice == "7":
            break
        else:
            print(random_color("Invalid choice, please try again."))

if __name__ == "__main__":
    main_menu()
