import pywifi
import scapy.all as scapy
import socket
import logging
from plyer import notification
import time
import tkinter as tk
from tkinter import scrolledtext
import threading

# Setup logging
logging.basicConfig(filename="wifi_risk_detector.log", 
                    level=logging.INFO, 
                    format="%(asctime)s - %(message)s")

# Notification Cooldown (seconds)
NOTIFICATION_COOLDOWN = 10
last_notification_time = 0  # Track the last notification time

# Notification Function with cooldown
def notify_user(message):
    global last_notification_time
    current_time = time.time()
    if current_time - last_notification_time > NOTIFICATION_COOLDOWN:
        notification.notify(
            title="Wi-Fi Security Alert",
            message=message,
            timeout=10  # Timeout may not be honored on all systems
        )
        print(message)  # Output to terminal for immediate feedback
        logging.info(message)  # Log the message
        last_notification_time = current_time

# Wi-Fi Scanning Function
def scan_wifi_networks():
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]  # Use the first interface
        iface.scan()  # Start scanning
        time.sleep(2)  # Allow some time for scan results
        networks = iface.scan_results()
        
        return [
            {
                'ssid': network.ssid,
                'signal': network.signal,
                'auth': network.akm[0] if network.akm else 'None',
                'frequency': network.freq
            }
            for network in networks
        ]
    except Exception as e:
        logging.error(f"Error scanning Wi-Fi networks: {str(e)}")
        notify_user("Error scanning Wi-Fi networks.")
        return []

# Analyze network for potential security risks
def analyze_network(network):
    risk_messages = []

    # Check authentication method
    if network['auth'] == 'None':
        risk_messages.append(f"Open network detected: {network['ssid']} – Unsecure!")
    elif network['auth'] == 'WEP':
        risk_messages.append(f"Weak encryption detected (WEP) on {network['ssid']} – Vulnerable!")
    
    # Check signal strength
    if network['signal'] < -80:
        risk_messages.append(f"Weak signal strength on {network['ssid']} – Risk of connection issues.")

    # Check SSID naming conventions
    common_ssids = ['guest', 'linksys', 'netgear', 'default']
    if any(common in network['ssid'].lower() for common in common_ssids):
        risk_messages.append(f"Common SSID detected: {network['ssid']} – Considered less secure.")

    # Frequency band check (2.4 GHz)
    if network['frequency'] < 2400:
        risk_messages.append(f"2.4 GHz band detected on {network['ssid']} – More prone to interference.")

    # Summarize the analysis
    if risk_messages:
        for message in risk_messages:
            notify_user(message)
            logging.warning(message)
        return f"Network {network['ssid']} has potential security risks."
    else:
        return f"Network {network['ssid']} appears secure."

# Check DNS Security
def check_dns_security():
    try:
        dns_server = socket.gethostbyname("example.com")
        high_risk_dns = ["8.8.8.8", "8.8.4.4"]  # Example high-risk DNS list
        
        if dns_server in high_risk_dns:
            message = f"Unsafe DNS Server detected: {dns_server}"
            notify_user(message)
            logging.warning(message)
            return message
        else:
            message = "DNS check completed: No high-risk DNS servers detected."
            notify_user(message)
            logging.info(message)
            return message
    except socket.gaierror:
        message = "Could not retrieve DNS server information – Potential risk!"
        notify_user(message)
        logging.error(message)
        return message

# Detect ARP Spoofing
def detect_arp_spoofing():
    arp_cache = {}
    alert_cooldown = 10  # Minimum seconds between consecutive alerts for the same IP
    last_alert_time = {}
    threats_found = False  # Track if any threats are found

    def process_packet(packet):
        nonlocal threats_found  # Allow nested function to modify this variable
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # ARP response
            src_ip = packet[scapy.ARP].psrc
            src_mac = packet[scapy.ARP].hwsrc

            # Detect if the IP is associated with multiple MAC addresses
            if src_ip in arp_cache:
                if arp_cache[src_ip] != src_mac:
                    current_time = time.time()
                    # Check if alert cooldown period has passed
                    if src_ip not in last_alert_time or (current_time - last_alert_time[src_ip]) > alert_cooldown:
                        message = f"Potential ARP spoofing detected from IP {src_ip} (MAC: {src_mac})!"
                        notify_user(message)
                        logging.warning(message)
                        last_alert_time[src_ip] = current_time
                        threats_found = True
            else:
                arp_cache[src_ip] = src_mac  # Update ARP cache

    scapy.sniff(store=False, prn=process_packet, timeout=60)
    
    # Provide feedback based on findings
    if threats_found:
        return "ARP spoofing detection finished. Threats found."
    else:
        return "ARP spoofing detection finished. No threats found."

# Detect SSL Stripping
def detect_ssl_strip():
    threats_found = False  # Track if any threats are found

    def process_packet(packet):
        nonlocal threats_found  # Allow nested function to modify this variable
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors="ignore")
            if "HTTP/1.1 301" in payload or "HTTP/1.1 302" in payload:
                message = "SSL stripping attack detected – HTTPS downgraded to HTTP!"
                notify_user(message)
                logging.warning(message)
                threats_found = True

    scapy.sniff(store=False, prn=process_packet, timeout=60)
    
    # Provide feedback based on findings
    if threats_found:
        return "SSL stripping detection finished. Threats found."
    else:
        return "SSL stripping detection finished. No threats found."

# GUI Application
class WifiRiskDetectorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Wi-Fi Risk Detector")
        self.master.geometry("500x400")

        self.text_area = scrolledtext.ScrolledText(master, width=60, height=15)
        self.text_area.pack(pady=10)

        self.scan_button = tk.Button(master, text="Scan Wi-Fi Networks", command=self.scan_wifi)
        self.scan_button.pack(pady=5)

        self.dns_button = tk.Button(master, text="Check DNS Security", command=self.check_dns)
        self.dns_button.pack(pady=5)

        self.arp_button = tk.Button(master, text="Detect ARP Spoofing", command=self.detect_arp)
        self.arp_button.pack(pady=5)

        self.ssl_button = tk.Button(master, text="Detect SSL Stripping", command=self.detect_ssl)
        self.ssl_button.pack(pady=5)

    def scan_wifi(self):
        self.text_area.delete(1.0, tk.END)  # Clear previous text
        networks = scan_wifi_networks()
        for network in networks:
            status = analyze_network(network)
            self.text_area.insert(tk.END, f"{status}\n")

    def check_dns(self):
        self.text_area.delete(1.0, tk.END)
        dns_status = check_dns_security()
        self.text_area.insert(tk.END, f"{dns_status}\n")

    def detect_arp(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, "Starting ARP spoofing detection for 60 seconds...\n")
        
        # Start the timer thread
        timer_thread = threading.Thread(target=self.run_timer, args=("Detecting ARP spoofing...",))
        timer_thread.start()

        # Start ARP detection in a new thread
        arp_thread = threading.Thread(target=self.run_arp_detection)
        arp_thread.start()

    def run_timer(self, initial_message):
        # Insert the initial message just once
        self.text_area.delete(1.0, tk.END)  # Clear previous text
        self.text_area.insert(tk.END, f"{initial_message} Time remaining: 60 seconds...")
        self.text_area.see(tk.END)  # Scroll to the end of the text area

        for remaining in range(59, 0, -1):  # 59 because we already displayed 60
            time.sleep(1)
            # Update the countdown on the same line
            self.text_area.delete(1.0, tk.END)  # Clear the text area
            self.text_area.insert(tk.END, f"{initial_message} Time remaining: {remaining} seconds...")
            self.text_area.see(tk.END)  # Scroll to the end of the text area

    def run_arp_detection(self):
        arp_status = detect_arp_spoofing()
        self.text_area.insert(tk.END, f"{arp_status}\n")

    def detect_ssl(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, "Starting SSL stripping detection for 60 seconds...\n")
        
        # Start the timer thread
        timer_thread = threading.Thread(target=self.run_timer_ssl, args=("Detecting SSL stripping...",))
        timer_thread.start()

        # Start SSL detection in a new thread
        ssl_thread = threading.Thread(target=self.run_ssl_detection)
        ssl_thread.start()

    def run_timer_ssl(self, initial_message):
        # Insert the initial message just once
        self.text_area.delete(1.0, tk.END)  # Clear previous text
        self.text_area.insert(tk.END, f"{initial_message} Time remaining: 60 seconds...")
        self.text_area.see(tk.END)  # Scroll to the end of the text area

        for remaining in range(59, 0, -1):  # 59 because we already displayed 60
            time.sleep(1)
            # Update the countdown on the same line
            self.text_area.delete(1.0, tk.END)  # Clear the text area
            self.text_area.insert(tk.END, f"{initial_message} Time remaining: {remaining} seconds...")
            self.text_area.see(tk.END)  # Scroll to the end of the text area

    def run_ssl_detection(self):
        ssl_status = detect_ssl_strip()
        self.text_area.insert(tk.END, f"{ssl_status}\n")

# Main function to run the GUI
def main():
    root = tk.Tk()
    app = WifiRiskDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
