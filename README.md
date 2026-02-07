# Network IDS/EDR for Linux

A comprehensive network-wide Intrusion Detection System (IDS) and Endpoint Detection and Response (EDR) tool for Linux. This system monitors your entire network for suspicious activity, discovers devices, detects threats, scans for vulnerabilities, and provides real-time alerts through an interactive dashboard.

---

##  Features

- **Network Discovery**: Automatically detects devices on your network using ARP and ping scanning
- **Traffic Analysis**: Monitors network traffic for suspicious patterns and potential attacks
- **Vulnerability Scanning**: Identifies open ports, services, and vulnerabilities on network devices
- **Wireless Monitoring**: Scans Wi-Fi networks for unauthorized access points and clients
- **Threat Intelligence**: Checks IPs against threat intelligence feeds (AbuseIPDB, VirusTotal)
- **Real-time Dashboard**: Interactive terminal-based dashboard showing network status and alerts
- **Alert System**: Detects and alerts on various threats including:
  - Port scanning
  - ARP spoofing
  - SYN/ICMP floods
  - DNS tunneling attempts
  - Suspicious port activity
- **Auto-blocking**: Automatically blocks malicious devices using iptables

---

##  Installation

### 1. Clone the Repository

```bash
git clone https://github.com/ekomsSavior/network_ids.git
cd network_ids
```

### 2. Install Dependencies

The tool requires several Python packages. Install them manually:

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip nmap iw wireless-tools


pip3 install psutil scapy netifaces python-nmap requests prettytable --break-system-packages
sudo pip3 install pandas --break-system-packages
```

**Note for Wi-Fi Monitoring**: If you plan to use wireless monitoring features, you'll need:
- A compatible Wi-Fi adapter that supports monitor mode

---

##  Setup

Before running the tool, you need to configure it:

```bash
# Make the script executable
chmod +x network_ids.py

# Run the setup (as regular user first)
sudo python3 network_ids.py
```

The setup wizard will:
1. Auto-detect your network range (or let you specify it manually)
2. Ask if you want to configure wireless monitoring
3. Create necessary configuration files
4. Check for required dependencies

---

##  Usage

### Running the System

```bash
# Run with sudo for full functionality (network scanning, iptables blocking)
sudo python3 network_ids.py
```

### Dashboard Commands

Once running, the interactive dashboard provides these commands:

- **S** - Scan network for new devices
- **A** - Perform active vulnerability scan
- **B** - Block a specific IP address
- **V** - View discovered vulnerabilities
- **L** - View alert logs
- **W** - Scan Wi-Fi networks
- **R** - Refresh dashboard
- **Q** - Quit the system

---

##  Configuration

### Wireless Monitoring

If you want to monitor Wi-Fi networks:

1. **Get a compatible Wi-Fi adapter** that supports monitor mode (common choices: Alfa AWUS036NHA, Panda PAU09)
2. **Install necessary drivers** for your adapter
3. **Put the adapter in monitor mode**:
   ```bash
   sudo ip link set wlan0 down
   sudo iwconfig wlan0 mode monitor
   sudo ip link set wlan0 up
   ```
4. **Update the configuration** in the setup wizard to use your adapter name

### API Keys (Optional)

For threat intelligence features, add your API keys in the configuration:
- VirusTotal API key
- AbuseIPDB API key
- Shodan API key (not implemented yet)

Edit the `CONFIG` dictionary in the script to add your keys.

---

##  Important Notes

### Network Interface
- The tool auto-detects your primary network interface
- For wireless monitoring, specify your wireless interface during setup
- Ensure your interface supports monitor mode

### Performance
- Active scanning may temporarily increase network load
- Consider adjusting scan intervals for large networks
- Running on a dedicated monitoring device is recommended

---

##  What It Monitors

### Network Threats
- New/unknown devices on network
- ARP spoofing and poisoning
- Port scanning activity
- DDoS attacks (SYN/ICMP floods)
- Suspicious port usage
- DNS tunneling attempts

### Device Information
- IP and MAC addresses
- Open ports and services
- Operating system detection
- Manufacturer information
- Hostname resolution

### Wireless Networks
- Available Wi-Fi networks
- Signal strength and channels
- Encryption status
- Connected clients

---

## Output Files

The system creates several data files:

- `network_devices.csv` - Discovered network devices
- `vulnerabilities.csv` - Found vulnerabilities
- `malicious_ips.txt` - Manually added malicious IPs
- `whitelist.json` - Trusted devices
- `/var/log/network_ids.log` - System logs

---

##  Disclaimer

**Only use on networks you have permission to test on**

![image0(1)](https://github.com/user-attachments/assets/6113d18f-ec5d-41ac-90dd-280751a60197)

