# Risk-detector
tool to check the risk of wifi, python
# Wi-Fi Risk Detector

**Wi-Fi Risk Detector** is a Python application designed to analyze Wi-Fi networks for potential security risks. It detects various vulnerabilities such as ARP spoofing, DNS security issues, and SSL stripping attacks, providing users with real-time notifications through a graphical user interface (GUI).

## Table of Contents

- [Project Overview](#project-overview)
- [Installation](#installation)
- [Features](#features)
- [Usage](#usage)
- [Code Structure](#code-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Project Overview

Wi-Fi Risk Detector scans available Wi-Fi networks, analyzes their security measures, and alerts users about potential vulnerabilities. This application aims to enhance user awareness and encourage secure Wi-Fi practices.

## Installation

### Prerequisites

Make sure you have the following installed:

- Python 3.6 or higher
- Pip (Python package manager)

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/wifi-risk-detector.git
   cd wifi-risk-detector
Install required packages: Run the following command to install necessary dependencies:
pip install pywifi scapy plyer
Features
Wi-Fi Network Scanning: Discover and analyze the security of nearby Wi-Fi networks.
ARP Spoofing Detection: Monitor ARP requests to identify potential spoofing attacks.
DNS Security Check: Evaluate the DNS server in use against known high-risk servers.
SSL Stripping Detection: Detect potential SSL stripping attacks in real-time.
User Notifications: Receive notifications for security alerts directly on your desktop.
Logging: All security alerts and actions are logged for future reference.
Usage
Scan Wi-Fi Networks:

Click the "Scan Wi-Fi Networks" button to view available networks and their security statuses.
Check DNS Security:

Click the "Check DNS Security" button to analyze the DNS server in use.
Detect ARP Spoofing:

Click the "Detect ARP Spoofing" button to initiate detection for 60 seconds, displaying a countdown timer.
Detect SSL Stripping:

Click the "Detect SSL Stripping" button to monitor for SSL stripping attacks for 60 seconds.
Code Structure
main.py: The main application file that contains the GUI and core functionality.
wifi_risk_detector.log: Log file that records all security alerts and notifications.
Contributing
We welcome contributions! If you would like to improve this project:

Fork the repository.
Create a new branch for your feature or bug fix.
Commit your changes.
Push to the branch.
Submit a pull request.
