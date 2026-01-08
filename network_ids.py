#!/usr/bin/env python3
"""
Network-Wide IDS/EDR System for Linux
Monitors entire network for suspicious activity
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import socket
import ipaddress
import re
from datetime import datetime
from collections import defaultdict
import psutil
import netifaces
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
import nmap
import pandas as pd
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
import hashlib
import requests
from prettytable import PrettyTable
import csv

# Configuration
CONFIG = {
    "scan_interval": 10,  # seconds
    "network_scan_interval": 300,  # 5 minutes
    "log_file": "/var/log/network_ids.log",
    "alert_threshold": 3,
    "whitelist_file": "whitelist.json",
    "malicious_ips_file": "malicious_ips.txt",
    "network_devices_file": "network_devices.csv",
    "vulnerabilities_file": "vulnerabilities.csv",
    "network_range": "192.168.1.0/24",  # Auto-detect or set manually
    "suspicious_ports": [4444, 31337, 6667, 1337, 12345, 22, 23, 3389, 5900, 21],
    "suspicious_processes": ["nc", "ncat", "socat", "meterpreter", "beacon", "backdoor", "c99", "r57"],
    "api_keys": {
        "virustotal": "",  # Add your API key
        "abuseipdb": "",   # Add your API key
        "shodan": ""       # Add your API key
    },
    "wireless_interface": "wlan0",  # Change to your wireless interface
    "active_scan_interval": 1800,  # 30 minutes for active scans
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Alert data structure"""
    timestamp: str
    alert_type: str
    severity: str
    description: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    device_mac: Optional[str] = None
    device_hostname: Optional[str] = None
    process: Optional[str] = None
    payload_preview: Optional[str] = None

@dataclass
class NetworkDevice:
    """Network device information"""
    ip: str
    mac: str
    hostname: str
    vendor: str
    os: str
    first_seen: str
    last_seen: str
    open_ports: List[int]
    services: Dict[int, str]
    is_trusted: bool
    risk_score: int
    vulnerabilities: List[str]

@dataclass
class Vulnerability:
    """Vulnerability information"""
    ip: str
    port: int
    service: str
    vulnerability: str
    severity: str
    cve: Optional[str]
    description: str
    discovered: str

class NetworkScanner:
    """Scan and monitor entire network"""
    
    def __init__(self):
        self.network_devices = {}
        self.device_history = defaultdict(list)
        self.arp_table = {}
        self.nm = nmap.PortScanner()
        self.network_range = self.detect_network_range()
        self.vulnerabilities = []
        self.wireless_networks = {}
        
    def detect_network_range(self) -> str:
        """Auto-detect network range"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # Get network info for interface
            addrs = netifaces.ifaddresses(interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip_addr = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network range
            network = ipaddress.ip_network(f"{ip_addr}/{netmask}", strict=False)
            return str(network)
            
        except Exception as e:
            logger.error(f"Failed to detect network: {e}")
            return CONFIG["network_range"]
    
    def arp_scan(self) -> Dict[str, str]:
        """Perform ARP scan to discover devices"""
        devices = {}
        
        # Create ARP request packet
        arp_request = ARP(pdst=self.network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        try:
            # Send packet and get responses
            answered, unanswered = srp(packet, timeout=2, verbose=False)
            
            for sent, received in answered:
                devices[received.psrc] = received.hwsrc
                
                # Log discovered device
                if received.psrc not in self.network_devices:
                    logger.info(f"Discovered device: {received.psrc} -> {received.hwsrc}")
                    
                    # Get vendor from MAC
                    vendor = self.get_mac_vendor(received.hwsrc)
                    
                    # Create device record
                    device = NetworkDevice(
                        ip=received.psrc,
                        mac=received.hwsrc,
                        hostname=self.resolve_hostname(received.psrc),
                        vendor=vendor,
                        os="Unknown",
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        open_ports=[],
                        services={},
                        is_trusted=False,
                        risk_score=0,
                        vulnerabilities=[]
                    )
                    
                    self.network_devices[received.psrc] = device
                else:
                    # Update last seen
                    self.network_devices[received.psrc].last_seen = datetime.now().isoformat()
                    
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            
        return devices
    
    def active_network_scan(self):
        """Perform comprehensive network scan"""
        logger.info("Starting active network scan...")
        alerts = []
        
        try:
            # Ping sweep to find active hosts
            print(f" Performing ping sweep on {self.network_range}...")
            ans, unans = sr(IP(dst=self.network_range)/ICMP(), timeout=2, verbose=0)
            
            active_hosts = [host[1].src for host in ans]
            print(f" Found {len(active_hosts)} active hosts")
            
            # Scan each active host
            for ip in active_hosts:
                print(f" Scanning {ip}...")
                
                # Service detection scan
                self.nm.scan(ip, '1-1000', '-sS -sV -O --version-intensity 5 -T4')
                
                if ip in self.nm.all_hosts():
                    device = self.network_devices.get(ip)
                    if not device:
                        # Create new device record
                        mac = self.get_mac_from_arp(ip)
                        device = NetworkDevice(
                            ip=ip,
                            mac=mac,
                            hostname=self.resolve_hostname(ip),
                            vendor=self.get_mac_vendor(mac),
                            os=self.nm[ip].get('osmatch', [{}])[0].get('name', 'Unknown') if self.nm[ip].get('osmatch') else 'Unknown',
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            open_ports=[],
                            services={},
                            is_trusted=False,
                            risk_score=0,
                            vulnerabilities=[]
                        )
                        self.network_devices[ip] = device
                    
                    # Update ports and services
                    for proto in self.nm[ip].all_protocols():
                        ports = self.nm[ip][proto].keys()
                        device.open_ports = list(ports)
                        
                        for port in ports:
                            service_info = self.nm[ip][proto][port]
                            device.services[port] = f"{service_info.get('name', 'unknown')} {service_info.get('version', '')}".strip()
                    
                    # Check for vulnerabilities
                    self.scan_vulnerabilities(ip)
                    
                    # Check for suspicious ports
                    for port in device.open_ports:
                        if port in CONFIG["suspicious_ports"]:
                            alert = Alert(
                                timestamp=datetime.now().isoformat(),
                                alert_type="SUSPICIOUS_PORT_OPEN",
                                severity="MEDIUM",
                                description=f"Device {ip} has suspicious port {port} open",
                                source_ip=ip,
                                dest_ip="N/A",
                                dest_port=port,
                                protocol="TCP"
                            )
                            alerts.append(alert)
            
            # Save results
            self.save_network_devices()
            logger.info(f"Active scan completed: {len(active_hosts)} hosts scanned")
            
        except Exception as e:
            logger.error(f"Active network scan failed: {e}")
        
        return alerts
    
    def scan_vulnerabilities(self, ip: str) -> List[Vulnerability]:
        """Scan for vulnerabilities on a device"""
        vulns = []
        
        try:
            logger.info(f"Scanning {ip} for vulnerabilities...")
            
            # Use nmap vulnerability scripts
            self.nm.scan(ip, arguments='--script vuln -T4')
            
            if ip in self.nm.all_hosts():
                for port in self.nm[ip]['tcp']:
                    if 'script' in self.nm[ip]['tcp'][port]:
                        scripts = self.nm[ip]['tcp'][port]['script']
                        
                        for script_name, script_output in scripts.items():
                            if any(keyword in script_name.lower() for keyword in ['vuln', 'exploit', 'cve']):
                                # Parse vulnerability information
                                vuln = Vulnerability(
                                    ip=ip,
                                    port=port,
                                    service=self.nm[ip]['tcp'][port].get('name', 'unknown'),
                                    vulnerability=script_name,
                                    severity=self.determine_severity(script_output),
                                    cve=self.extract_cve(script_output),
                                    description=script_output[:200] + "..." if len(script_output) > 200 else script_output,
                                    discovered=datetime.now().isoformat()
                                )
                                vulns.append(vuln)
                                
                                # Update device vulnerabilities
                                if ip in self.network_devices:
                                    self.network_devices[ip].vulnerabilities.append(script_name)
                                    # Increase risk score based on vulnerability severity
                                    if vuln.severity == "HIGH":
                                        self.network_devices[ip].risk_score += 5
                                    elif vuln.severity == "MEDIUM":
                                        self.network_devices[ip].risk_score += 3
                                    else:
                                        self.network_devices[ip].risk_score += 1
                
                # Save vulnerabilities
                self.save_vulnerabilities(vulns)
                logger.info(f"Found {len(vulns)} vulnerabilities on {ip}")
        
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {ip}: {e}")
        
        return vulns
    
    def determine_severity(self, output: str) -> str:
        """Determine vulnerability severity from output"""
        output_lower = output.lower()
        if 'critical' in output_lower or 'high' in output_lower:
            return "HIGH"
        elif 'medium' in output_lower:
            return "MEDIUM"
        elif 'low' in output_lower:
            return "LOW"
        return "INFO"
    
    def extract_cve(self, output: str) -> Optional[str]:
        """Extract CVE ID from output"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, output.upper())
        return matches[0] if matches else None
    
    def monitor_wifi(self):
        """Monitor Wi-Fi networks and clients"""
        try:
            logger.info("Starting Wi-Fi monitoring...")
            
            # Check if interface exists and is in monitor mode
            if not self.check_wireless_interface():
                logger.warning("Wireless interface not available for monitoring")
                return
            
            # Use iwconfig to scan for networks
            cmd = ["sudo", "iwlist", CONFIG["wireless_interface"], "scan"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.parse_wireless_scan(result.stdout)
            else:
                # Try alternative method
                cmd = ["sudo", "iw", "dev", CONFIG["wireless_interface"], "scan"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.parse_iw_scan(result.stdout)
        
        except Exception as e:
            logger.error(f"Wi-Fi monitoring failed: {e}")
    
    def check_wireless_interface(self) -> bool:
        """Check if wireless interface is available"""
        try:
            # Check if interface exists
            interfaces = netifaces.interfaces()
            if CONFIG["wireless_interface"] not in interfaces:
                logger.warning(f"Interface {CONFIG['wireless_interface']} not found")
                return False
            
            # Check if it's a wireless interface
            cmd = ["iw", "dev", CONFIG["wireless_interface"], "info"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Interface check failed: {e}")
            return False
    
    def parse_wireless_scan(self, output: str):
        """Parse iwlist scan output"""
        networks = {}
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell' in line:
                # New network
                if current_network:
                    networks[current_network.get('essid', 'Unknown')] = current_network
                current_network = {}
            
            elif 'ESSID:' in line:
                essid = line.split('ESSID:"')[1].rstrip('"')
                current_network['essid'] = essid
            
            elif 'Address:' in line:
                mac = line.split('Address:')[1].strip()
                current_network['mac'] = mac
            
            elif 'Channel:' in line:
                channel = line.split('Channel:')[1].strip()
                current_network['channel'] = channel
            
            elif 'Quality=' in line:
                quality_match = re.search(r'Quality=(\d+/\d+)', line)
                if quality_match:
                    current_network['quality'] = quality_match.group(1)
            
            elif 'Encryption key:' in line:
                encrypted = 'on' in line
                current_network['encrypted'] = encrypted
        
        # Add last network
        if current_network:
            networks[current_network.get('essid', 'Unknown')] = current_network
        
        self.wireless_networks = networks
        logger.info(f"Found {len(networks)} wireless networks")
    
    def parse_iw_scan(self, output: str):
        """Parse iw scan output"""
        networks = {}
        current_bss = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('BSS'):
                # New BSS
                if current_bss:
                    networks[current_bss.get('ssid', 'Unknown')] = current_bss
                current_bss = {}
                mac = line.split()[1]
                current_bss['mac'] = mac
            
            elif 'SSID:' in line:
                ssid = line.split('SSID:')[1].strip()
                current_bss['ssid'] = ssid
            
            elif 'freq:' in line:
                freq = line.split('freq:')[1].strip()
                current_bss['channel'] = self.freq_to_channel(int(freq))
        
        # Add last BSS
        if current_bss:
            networks[current_bss.get('ssid', 'Unknown')] = current_bss
        
        self.wireless_networks = networks
    
    def freq_to_channel(self, freq: int) -> int:
        """Convert frequency to channel number"""
        if 2412 <= freq <= 2484:
            return (freq - 2412) // 5 + 1
        elif 5170 <= freq <= 5825:
            return (freq - 5170) // 5 + 34
        return 0
    
    def port_scan_device(self, ip: str) -> List[Alert]:
        """Scan a device for open ports"""
        alerts = []
        
        try:
            # Quick scan for common ports
            self.nm.scan(ip, '20-1024', arguments='-sS -T4')
            
            if ip in self.nm.all_hosts():
                # Update device information
                device = self.network_devices.get(ip)
                if device:
                    device.open_ports = list(self.nm[ip].all_tcp().keys())
                    
                    # Check for suspicious ports
                    for port in device.open_ports:
                        if port in CONFIG["suspicious_ports"]:
                            alert = Alert(
                                timestamp=datetime.now().isoformat(),
                                alert_type="SUSPICIOUS_PORT_OPEN",
                                severity="MEDIUM",
                                description=f"Device {ip} has suspicious port {port} open",
                                source_ip=ip,
                                dest_ip="N/A",
                                dest_port=port,
                                protocol="TCP"
                            )
                            alerts.append(alert)
                            
        except Exception as e:
            logger.error(f"Port scan failed for {ip}: {e}")
            
        return alerts
    
    def network_discovery_loop(self):
        """Continuous network discovery"""
        while True:
            try:
                logger.info(f"Scanning network: {self.network_range}")
                devices = self.arp_scan()
                
                # Check for new/unknown devices
                known_ips = set(self.load_known_devices())
                current_ips = set(devices.keys())
                
                # Alert on new devices
                new_devices = current_ips - known_ips
                for ip in new_devices:
                    mac = devices[ip]
                    logger.warning(f"New device detected: {ip} ({mac})")
                
                # Save current devices
                self.save_network_devices()
                
                # Perform port scans on new devices
                for ip in new_devices:
                    self.port_scan_device(ip)
                
            except Exception as e:
                logger.error(f"Network discovery error: {e}")
                
            time.sleep(CONFIG["network_scan_interval"])
    
    def monitor_network_traffic(self):
        """Monitor all network traffic"""
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check if source or destination is in our network
                src_in_network = ipaddress.ip_address(src_ip) in ipaddress.ip_network(self.network_range)
                dst_in_network = ipaddress.ip_address(dst_ip) in ipaddress.ip_network(self.network_range)
                
                # Only monitor traffic involving our network
                if src_in_network or dst_in_network:
                    alert = self.analyze_packet(packet)
                    if alert:
                        # Handle alert (will be implemented in main class)
                        pass
        
        try:
            # Start sniffing
            sniff(prn=packet_callback, store=0, filter="ip", count=0)
        except Exception as e:
            logger.error(f"Traffic monitoring failed: {e}")
    
    def analyze_packet(self, packet) -> Optional[Alert]:
        """Analyze individual packets for threats"""
        alert = None
        
        try:
            # TCP packets
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Check for port scanning
                if dst_port in CONFIG["suspicious_ports"]:
                    alert = Alert(
                        timestamp=datetime.now().isoformat(),
                        alert_type="SUSPICIOUS_TRAFFIC",
                        severity="MEDIUM",
                        description=f"Suspicious traffic on port {dst_port}",
                        source_ip=packet[IP].src,
                        dest_ip=packet[IP].dst,
                        source_port=src_port,
                        dest_port=dst_port,
                        protocol="TCP"
                    )
                
                # Check for SYN flood (DDoS)
                if packet[TCP].flags == 'S':  # SYN packet
                    key = f"{packet[IP].src}:{src_port}"
                    self.device_history[key].append(time.time())
                    
                    # Check rate
                    cutoff = time.time() - 1  # Last second
                    recent = [t for t in self.device_history[key] if t > cutoff]
                    
                    if len(recent) > 100:  # More than 100 SYN packets per second
                        alert = Alert(
                            timestamp=datetime.now().isoformat(),
                            alert_type="SYN_FLOOD",
                            severity="HIGH",
                            description=f"Possible SYN flood from {packet[IP].src}",
                            source_ip=packet[IP].src,
                            dest_ip=packet[IP].dst,
                            source_port=src_port,
                            dest_port=dst_port,
                            protocol="TCP"
                        )
            
            # ICMP packets (ping flood)
            elif ICMP in packet:
                key = packet[IP].src
                self.device_history[key].append(time.time())
                
                cutoff = time.time() - 1
                recent = [t for t in self.device_history[key] if t > cutoff]
                
                if len(recent) > 50:  # More than 50 ICMP packets per second
                    alert = Alert(
                        timestamp=datetime.now().isoformat(),
                        alert_type="ICMP_FLOOD",
                        severity="HIGH",
                        description=f"Possible ICMP flood from {packet[IP].src}",
                        source_ip=packet[IP].src,
                        dest_ip=packet[IP].dst,
                        protocol="ICMP"
                    )
            
            # DNS queries (check for DNS tunneling)
            elif UDP in packet and packet[UDP].dport == 53:
                # Basic DNS tunneling detection - long domain names
                if hasattr(packet, 'DNS') and hasattr(packet.DNS, 'qd'):
                    query = str(packet.DNS.qd.qname)
                    if len(query) > 50:  # Suspiciously long DNS query
                        alert = Alert(
                            timestamp=datetime.now().isoformat(),
                            alert_type="DNS_TUNNELING_SUSPECTED",
                            severity="MEDIUM",
                            description=f"Possible DNS tunneling: long query from {packet[IP].src}",
                            source_ip=packet[IP].src,
                            dest_ip=packet[IP].dst,
                            source_port=packet[UDP].sport,
                            dest_port=53,
                            protocol="DNS",
                            payload_preview=query[:100]
                        )
        
        except Exception as e:
            logger.error(f"Packet analysis error: {e}")
        
        return alert
    
    def get_mac_from_arp(self, ip: str) -> str:
        """Get MAC address from ARP cache"""
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        return parts[3]
        except:
            pass
        return "00:00:00:00:00:00"
    
    def get_mac_vendor(self, mac: str) -> str:
        """Get vendor from MAC address"""
        try:
            # First 3 octets are OUI
            oui = mac[:8].replace(':', '').upper()
            
            # Use local OUI database or API
            oui_db = {
                "000C29": "VMware",
                "005056": "VMware",
                "000569": "Netgear",
                "001B2F": "NETGEAR",
                "F0DEF1": "Wistron",
                "0016EA": "Cisco",
                "001CC1": "Cisco",
                "A4BBAF": "Huawei",
                "F8A963": "Huawei",
                "001E65": "Apple",
                "0016CB": "Apple",
                "001B63": "Apple"
            }
            
            return oui_db.get(oui, "Unknown")
        except:
            return "Unknown"
    
    def resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def load_known_devices(self) -> List[str]:
        """Load known devices from file"""
        try:
            if os.path.exists(CONFIG["network_devices_file"]):
                df = pd.read_csv(CONFIG["network_devices_file"])
                return df['ip'].tolist()
        except:
            pass
        return []
    
    def save_network_devices(self):
        """Save network devices to CSV"""
        try:
            devices_list = []
            for ip, device in self.network_devices.items():
                device_dict = asdict(device)
                # Convert lists to strings for CSV
                device_dict['open_ports'] = ','.join(map(str, device_dict['open_ports']))
                device_dict['services'] = str(device_dict['services'])
                device_dict['vulnerabilities'] = ','.join(device_dict['vulnerabilities'])
                devices_list.append(device_dict)
            
            df = pd.DataFrame(devices_list)
            df.to_csv(CONFIG["network_devices_file"], index=False)
            logger.info(f"Saved {len(devices_list)} devices to {CONFIG['network_devices_file']}")
        except Exception as e:
            logger.error(f"Failed to save devices: {e}")
    
    def save_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        """Save vulnerabilities to CSV"""
        try:
            vuln_list = [asdict(v) for v in vulnerabilities]
            
            # Load existing vulnerabilities
            existing_vulns = []
            if os.path.exists(CONFIG["vulnerabilities_file"]):
                existing_df = pd.read_csv(CONFIG["vulnerabilities_file"])
                existing_vulns = existing_df.to_dict('records')
            
            # Combine and remove duplicates
            all_vulns = existing_vulns + vuln_list
            unique_vulns = []
            seen = set()
            
            for vuln in all_vulns:
                key = (vuln['ip'], vuln['port'], vuln['vulnerability'])
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(vuln)
            
            df = pd.DataFrame(unique_vulns)
            df.to_csv(CONFIG["vulnerabilities_file"], index=False)
            logger.info(f"Saved {len(unique_vulns)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Failed to save vulnerabilities: {e}")

class ThreatIntelligence:
    """Check IPs against threat intelligence feeds"""
    
    def __init__(self):
        self.cache = {}
        
    def check_ip_reputation(self, ip: str) -> Dict:
        """Check IP against multiple threat feeds"""
        reputation = {
            "score": 0,
            "threats": [],
            "sources": []
        }
        
        # Check cache first
        if ip in self.cache and (time.time() - self.cache[ip]['timestamp']) < 3600:
            return self.cache[ip]['data']
        
        try:
            # Check AbuseIPDB
            if CONFIG["api_keys"]["abuseipdb"]:
                result = self.check_abuseipdb(ip)
                reputation["score"] += result.get("score", 0)
                reputation["threats"].extend(result.get("threats", []))
                reputation["sources"].append("AbuseIPDB")
            
            # Check VirusTotal
            if CONFIG["api_keys"]["virustotal"]:
                result = self.check_virustotal(ip)
                reputation["score"] += result.get("score", 0)
                reputation["threats"].extend(result.get("threats", []))
                reputation["sources"].append("VirusTotal")
            
            # Cache result
            self.cache[ip] = {
                'timestamp': time.time(),
                'data': reputation
            }
            
        except Exception as e:
            logger.error(f"Threat intelligence check failed: {e}")
        
        return reputation
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """Check IP against AbuseIPDB"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': CONFIG["api_keys"]["abuseipdb"],
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                abuse_score = data['data']['abuseConfidenceScore']
                threats = []
                
                if abuse_score > 50:
                    threats.append(f"AbuseIPDB score: {abuse_score}%")
                
                return {
                    "score": abuse_score / 10,  # Normalize to 0-10
                    "threats": threats
                }
        except:
            pass
        return {"score": 0, "threats": []}
    
    def check_virustotal(self, ip: str) -> Dict:
        """Check IP against VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                'x-apikey': CONFIG["api_keys"]["virustotal"]
            }
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats['malicious']
                suspicious = stats['suspicious']
                threats = []
                
                if malicious > 0:
                    threats.append(f"VirusTotal: {malicious} engines flagged as malicious")
                if suspicious > 0:
                    threats.append(f"VirusTotal: {suspicious} engines flagged as suspicious")
                
                score = (malicious * 2) + suspicious
                return {
                    "score": min(score, 10),  # Cap at 10
                    "threats": threats
                }
        except:
            pass
        return {"score": 0, "threats": []}

class NetworkIDS:
    """Main Network IDS System"""
    
    def __init__(self):
        self.running = False
        self.network_scanner = NetworkScanner()
        self.threat_intel = ThreatIntelligence()
        self.alerts = []
        self.dashboard_data = {
            "total_devices": 0,
            "suspicious_devices": 0,
            "active_threats": 0,
            "bandwidth_usage": 0,
            "recent_alerts": [],
            "vulnerabilities_count": 0,
            "wireless_networks": 0
        }
        self.last_active_scan = 0
        
    def start(self):
        """Start the network IDS"""
        logger.info("Starting Network IDS/EDR System...")
        self.running = True
        
        print(f"\n Network Range: {self.network_scanner.network_range}")
        print(" Starting network monitoring...")
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.network_scanner.network_discovery_loop),
            threading.Thread(target=self.network_scanner.monitor_network_traffic),
            threading.Thread(target=self.continuous_monitoring),
            threading.Thread(target=self.display_dashboard),
            threading.Thread(target=self.active_scan_scheduler)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        logger.info("Network IDS started successfully")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def active_scan_scheduler(self):
        """Schedule active scans"""
        while self.running:
            current_time = time.time()
            if current_time - self.last_active_scan > CONFIG["active_scan_interval"]:
                print("\n Scheduled active scan starting...")
                alerts = self.network_scanner.active_network_scan()
                for alert in alerts:
                    self.handle_alert(alert)
                self.last_active_scan = current_time
            time.sleep(60)  # Check every minute
    
    def continuous_monitoring(self):
        """Continuous monitoring loop"""
        while self.running:
            # Check for ARP spoofing
            self.detect_arp_spoofing()
            
            # Check for unusual traffic patterns
            self.detect_anomalies()
            
            # Monitor Wi-Fi networks
            self.network_scanner.monitor_wifi()
            
            # Update dashboard data
            self.update_dashboard()
            
            time.sleep(CONFIG["scan_interval"])
    
    def detect_arp_spoofing(self):
        """Detect ARP spoofing attacks"""
        try:
            # Get current ARP table
            current_arp = self.network_scanner.arp_scan()
            
            # Check for multiple IPs with same MAC (ARP spoofing)
            mac_to_ips = defaultdict(list)
            for ip, mac in current_arp.items():
                mac_to_ips[mac].append(ip)
            
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    alert = Alert(
                        timestamp=datetime.now().isoformat(),
                        alert_type="ARP_SPOOFING_DETECTED",
                        severity="HIGH",
                        description=f"Possible ARP spoofing: MAC {mac} has multiple IPs {ips}",
                        source_ip=ips[0],
                        dest_ip="N/A",
                        device_mac=mac
                    )
                    self.handle_alert(alert)
                    
        except Exception as e:
            logger.error(f"ARP spoofing detection failed: {e}")
    
    def detect_anomalies(self):
        """Detect network anomalies"""
        # Check for unusual port activity
        for ip, device in self.network_scanner.network_devices.items():
            if len(device.open_ports) > 20:  # Too many open ports
                alert = Alert(
                    timestamp=datetime.now().isoformat(),
                    alert_type="EXCESSIVE_OPEN_PORTS",
                    severity="MEDIUM",
                    description=f"Device {ip} has {len(device.open_ports)} open ports",
                    source_ip=ip,
                    dest_ip="N/A"
                )
                self.handle_alert(alert)
    
    def handle_alert(self, alert: Alert):
        """Handle and log alerts"""
        self.alerts.append(alert)
        self.dashboard_data["recent_alerts"].append(alert)
        
        # Keep only last 50 alerts
        if len(self.dashboard_data["recent_alerts"]) > 50:
            self.dashboard_data["recent_alerts"].pop(0)
        
        # Log alert
        logger.warning(
            f"[{alert.severity}] {alert.alert_type}: {alert.description} "
            f"From: {alert.source_ip} -> To: {alert.dest_ip}"
        )
        
        # Console notification
        if alert.severity in ["HIGH", "CRITICAL"]:
            print(f"\n ALERT: {alert.alert_type}")
            print(f"   {alert.description}")
            print(f"   Source: {alert.source_ip}")
            if alert.dest_ip != "N/A":
                print(f"   Destination: {alert.dest_ip}")
            
            # Take action for critical alerts
            if alert.severity == "CRITICAL":
                self.block_device(alert.source_ip)
    
    def block_device(self, ip: str):
        """Block a device using iptables"""
        try:
            # Check if already blocked
            check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(check_cmd, capture_output=True)
            
            if result.returncode != 0:
                # Block device
                block_cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(block_cmd, check=True)
                
                # Also block from accessing other devices
                forward_cmd = ["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
                subprocess.run(forward_cmd, check=True)
                
                logger.info(f"Blocked device: {ip}")
                print(f" Blocked device: {ip}")
        except Exception as e:
            logger.error(f"Failed to block device {ip}: {e}")
    
    def update_dashboard(self):
        """Update dashboard data"""
        self.dashboard_data["total_devices"] = len(self.network_scanner.network_devices)
        
        # Count suspicious devices
        suspicious = 0
        vulnerability_count = 0
        for device in self.network_scanner.network_devices.values():
            if device.risk_score > 5:
                suspicious += 1
            vulnerability_count += len(device.vulnerabilities)
        
        self.dashboard_data["suspicious_devices"] = suspicious
        self.dashboard_data["active_threats"] = len([a for a in self.alerts if a.severity in ["HIGH", "CRITICAL"]])
        self.dashboard_data["vulnerabilities_count"] = vulnerability_count
        self.dashboard_data["wireless_networks"] = len(self.network_scanner.wireless_networks)
    
    def display_dashboard(self):
        """Display real-time dashboard"""
        while self.running:
            os.system('clear' if os.name == 'posix' else 'cls')
            
            print("\n" + "="*80)
            print(" NETWORK IDS/EDR DASHBOARD")
            print("="*80)
            
            # Network Overview
            print("\n NETWORK OVERVIEW")
            print(f"   Network Range: {self.network_scanner.network_range}")
            print(f"   Total Devices: {self.dashboard_data['total_devices']}")
            print(f"   Suspicious Devices: {self.dashboard_data['suspicious_devices']}")
            print(f"   Active Threats: {self.dashboard_data['active_threats']}")
            print(f"   Vulnerabilities: {self.dashboard_data['vulnerabilities_count']}")
            print(f"   Wireless Networks: {self.dashboard_data['wireless_networks']}")
            print(f"   Total Alerts: {len(self.alerts)}")
            
            # Recent Alerts
            print("\n RECENT ALERTS")
            recent_alerts = self.dashboard_data["recent_alerts"][-5:]  # Last 5 alerts
            if recent_alerts:
                for alert in reversed(recent_alerts):
                    severity_icon = "🔴" if alert.severity == "CRITICAL" else "🟡" if alert.severity == "HIGH" else "🟠"
                    print(f"   {severity_icon} [{alert.timestamp[11:19]}] {alert.alert_type}")
                    print(f"      {alert.description}")
            else:
                print("   No recent alerts")
            
            # Network Devices Table
            print("\n NETWORK DEVICES")
            if self.network_scanner.network_devices:
                table = PrettyTable()
                table.field_names = ["IP Address", "MAC", "Hostname", "Open Ports", "Risk", "Vulns"]
                table.align = "l"
                
                for ip, device in list(self.network_scanner.network_devices.items())[:8]:  # Show first 8
                    risk_level = "🟢" if device.risk_score < 3 else "🟡" if device.risk_score < 7 else "🔴"
                    ports = ", ".join(map(str, device.open_ports[:2])) + ("..." if len(device.open_ports) > 2 else "")
                    vulns = len(device.vulnerabilities)
                    table.add_row([ip, device.mac[:8]+"...", device.hostname[:12], ports, risk_level, vulns])
                
                print(table)
                if len(self.network_scanner.network_devices) > 8:
                    print(f"   ... and {len(self.network_scanner.network_devices) - 8} more devices")
            else:
                print("   No devices discovered yet")
            
            # Wireless Networks
            if self.network_scanner.wireless_networks:
                print("\n WIRELESS NETWORKS")
                table = PrettyTable()
                table.field_names = ["SSID", "MAC", "Channel", "Encrypted"]
                table.align = "l"
                
                for ssid, network in list(self.network_scanner.wireless_networks.items())[:5]:
                    table.add_row([
                        ssid[:15],
                        network.get('mac', 'Unknown')[:8] + "...",
                        network.get('channel', 'Unknown'),
                        "Yes" if network.get('encrypted') else "No"
                    ])
                
                print(table)
            
            # Bandwidth Usage
            print("\n BANDWIDTH MONITORING")
            try:
                net_io = psutil.net_io_counters()
                print(f"   Bytes Sent: {net_io.bytes_sent / 1024 / 1024:.2f} MB")
                print(f"   Bytes Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB")
            except:
                print("   Bandwidth data unavailable")
            
            # Commands
            print("\n COMMANDS")
            print("   [S] Scan Network  [A] Active Scan  [B] Block IP  [V] View Vulnerabilities")
            print("   [L] View Logs     [W] Wi-Fi Scan   [R] Refresh   [Q] Quit")
            print("="*80)
            
            # Check for user input
            self.check_user_input()
            
            time.sleep(2)  # Refresh every 2 seconds
    
    def check_user_input(self):
        """Check for user commands"""
        import select
        import sys
        
        if select.select([sys.stdin], [], [], 0.1)[0]:
            cmd = sys.stdin.readline().strip().upper()
            
            if cmd == 'Q':
                self.stop()
            elif cmd == 'S':
                print("\n Scanning network...")
                self.network_scanner.arp_scan()
            elif cmd == 'A':
                print("\n Starting active scan...")
                alerts = self.network_scanner.active_network_scan()
                for alert in alerts:
                    self.handle_alert(alert)
                print(" Active scan completed")
                time.sleep(2)
            elif cmd == 'B':
                ip = input("\nEnter IP to block: ")
                self.block_device(ip)
                time.sleep(2)
            elif cmd == 'V':
                self.show_vulnerabilities()
            elif cmd == 'W':
                print("\n Scanning Wi-Fi networks...")
                self.network_scanner.monitor_wifi()
                time.sleep(2)
            elif cmd == 'L':
                self.show_logs()
            elif cmd == 'R':
                pass  # Just refresh
    
    def show_vulnerabilities(self):
        """Display discovered vulnerabilities"""
        os.system('clear')
        print("\n  DISCOVERED VULNERABILITIES")
        print("="*80)
        
        if os.path.exists(CONFIG["vulnerabilities_file"]):
            try:
                df = pd.read_csv(CONFIG["vulnerabilities_file"])
                if not df.empty:
                    table = PrettyTable()
                    table.field_names = ["IP", "Port", "Vulnerability", "Severity", "CVE"]
                    
                    for _, row in df.iterrows():
                        severity_icon = "🔴" if row['severity'] == "HIGH" else "🟡" if row['severity'] == "MEDIUM" else "🟠"
                        table.add_row([
                            row['ip'],
                            row['port'],
                            row['vulnerability'][:20] + "..." if len(row['vulnerability']) > 20 else row['vulnerability'],
                            severity_icon,
                            row['cve'] if pd.notna(row['cve']) else "N/A"
                        ])
                    
                    print(table)
                    print(f"\nTotal vulnerabilities: {len(df)}")
                else:
                    print("No vulnerabilities found yet")
            except Exception as e:
                print(f"Error reading vulnerabilities: {e}")
        else:
            print("No vulnerability data available")
        
        input("\nPress Enter to return to dashboard...")
    
    def show_logs(self):
        """Display recent logs"""
        os.system('clear')
        print("\n RECENT ALERTS LOG")
        print("="*80)
        
        for alert in self.alerts[-20:]:  # Last 20 alerts
            print(f"\n[{alert.timestamp}] {alert.alert_type}")
            print(f"  Severity: {alert.severity}")
            print(f"  Description: {alert.description}")
            print(f"  Source: {alert.source_ip} -> Destination: {alert.dest_ip}")
        
        input("\nPress Enter to return to dashboard...")
    
    def stop(self):
        """Stop the system"""
        self.running = False
        logger.info("Network IDS stopped")
        print("\n Network IDS stopped")
        sys.exit(0)

def install_dependencies():
    """Install required dependencies"""
    print("\n Installing dependencies...")
    
    dependencies = [
        "psutil",
        "scapy",
        "netifaces",
        "python-nmap",
        "pandas",
        "requests",
        "prettytable"
    ]
    
    try:
        for dep in dependencies:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
        print(" Dependencies installed successfully")
    except Exception as e:
        print(f" Error: {e}")
        print("Install manually: pip install psutil scapy netifaces python-nmap pandas requests prettytable")

def setup_network_ids():
    """Setup network IDS"""
    print("\n" + "="*60)
    print(" Linux Network IDS/EDR Setup")
    print("="*60)
    
    print("\n  Configuration:")
    print("1. Auto-detect network range")
    print("2. Enter network range manually")
    print("3. Use default (192.168.1.0/24)")
    
    choice = input("\nSelect option (1-3): ")
    
    if choice == '2':
        network = input("Enter network range (e.g., 192.168.1.0/24): ")
        CONFIG["network_range"] = network
    elif choice == '1':
        print("Auto-detecting network...")
        scanner = NetworkScanner()
        CONFIG["network_range"] = scanner.network_range
        print(f"Detected network: {scanner.network_range}")
    
    # Ask for wireless interface
    wireless = input("\nConfigure wireless monitoring? (y/n): ")
    if wireless.lower() == 'y':
        interface = input("Enter wireless interface name (e.g., wlan0): ")
        CONFIG["wireless_interface"] = interface
    
    # Check for root
    if os.geteuid() != 0:
        print("\n  Warning: Some features require root privileges")
        print("   Run with: sudo python3 network_ids.py")
    
    # Create files if they don't exist
    files_to_create = {
        "malicious_ips.txt": "# Add malicious IPs here (one per line)\n# Example:\n# 192.168.1.100\n# 10.0.0.50\n",
        "whitelist.json": '{"devices": []}',
        "network_devices.csv": "ip,mac,hostname,vendor,os,first_seen,last_seen,open_ports,services,is_trusted,risk_score,vulnerabilities\n",
        "vulnerabilities.csv": "ip,port,service,vulnerability,severity,cve,description,discovered\n"
    }
    
    for filename, content in files_to_create.items():
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write(content)
            print(f" Created {filename}")
    
    print("\n Setup complete!")

if __name__ == "__main__":
    # Setup
    setup_network_ids()
    
    # Install dependencies if needed
    try:
        import psutil
        import scapy
        import netifaces
        import nmap
        import pandas
        import requests
        from prettytable import PrettyTable
    except ImportError:
        print("\n  Missing dependencies detected!")
        response = input("Install dependencies? (y/n): ")
        if response.lower() == 'y':
            install_dependencies()
        else:
            print("Please install dependencies manually: pip install psutil scapy netifaces python-nmap pandas requests prettytable")
            sys.exit(1)
    
    # Start
    print("\n Starting Network IDS...")
    print("Press Ctrl+C to stop\n")
    
    network_ids = NetworkIDS()
    
    try:
        network_ids.start()
    except KeyboardInterrupt:
        network_ids.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f" Error: {e}")
