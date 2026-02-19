#!/usr/bin/env python3
"""
Educational Packet Sniffer
FOR AUTHORIZED EDUCATIONAL USE ONLY

Usage:
    sudo python3 packet_sniffer.py [--interface INTERFACE] [--filter PROTOCOL] [--count NUM]
    
Examples:
    sudo python3 packet_sniffer.py
    sudo python3 packet_sniffer.py --interface eth0 --filter tcp --count 10
"""

import argparse
import socket
import struct
import textwrap
from datetime import datetime
import sys
import os
import signal

# Ethical usage warning
def display_ethical_warning():
    print("=" * 70)
    print("EDUCATIONAL PACKET SNIFFER - FOR AUTHORIZED USE ONLY")
    print("=" * 70)
    print("\nETHICAL USAGE WARNING:")
    print("1. Only use on networks you own or have explicit permission to monitor")
    print("2. Do not capture sensitive information (passwords, personal data)")
    print("3. This tool is for educational purposes only")
    print("4. Unauthorized network monitoring may be illegal")
    print("=" * 70)
    
    response = input("\nDo you agree to use this tool ethically? (yes/no): ")
    if response.lower() != 'yes':
        print("Exiting...")
        sys.exit(0)
    print("\n")

class EthicalPacketSniffer:
    def __init__(self, interface=None, protocol_filter=None, packet_count=50):
        self.interface = interface
        self.protocol_filter = protocol_filter.lower() if protocol_filter else None
        self.packet_count = packet_count
        self.captured_count = 0
        
        # Sensitive data filters (for ethical use)
        self.sensitive_patterns = [
            b'password', b'passwd', b'pwd', b'secret',
            b'credit', b'card', b'ssn', b'social',
            b'login', b'auth', b'token', b'key'
        ]
        
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        print(f"\n\nCaptured {self.captured_count} packets. Exiting...")
        sys.exit(0)
    
    def get_interface(self):
        """Get network interface to sniff on"""
        if self.interface:
            return self.interface
            
        # List available interfaces
        print("Available network interfaces:")
        interfaces = os.listdir('/sys/class/net/')
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        
        try:
            choice = int(input("\nSelect interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
        except:
            pass
            
        return 'eth0' if 'eth0' in interfaces else interfaces[0] if interfaces else None
    
    def create_socket(self):
        """Create raw socket for packet capturing"""
        try:
            # Create raw socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Set timeout to prevent blocking indefinitely
            s.settimeout(2)
            
            return s
        except PermissionError:
            print("Error: Root privileges required. Use sudo.")
            sys.exit(1)
        except Exception as e:
            print(f"Error creating socket: {e}")
            sys.exit(1)
    
    def format_multi_line(self, prefix, string, size=80):
        """Format multi-line data display"""
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
    def contains_sensitive_data(self, data):
        """Check if data contains potentially sensitive information"""
        if not data:
            return False
        
        data_lower = data.lower()
        for pattern in self.sensitive_patterns:
            if pattern in data_lower:
                return True
        return False
    
    def mask_sensitive_data(self, data):
        """Mask potentially sensitive data"""
        if not data or len(data) < 8:
            return "[DATA TOO SHORT OR ENCRYPTED]"
        
        if self.contains_sensitive_data(data):
            return "[SENSITIVE DATA - REDACTED FOR ETHICAL REASONS]"
        
        # Show first 100 bytes only
        if len(data) > 100:
            return data[:100].hex() + "... [TRUNCATED]"
        
        return data.hex()
    
    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]
    
    def get_mac_addr(self, bytes_addr):
        """Format MAC address"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    def parse_ip_packet(self, data):
        """Parse IP packet"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]
    
    def ipv4(self, addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))
    
    def parse_tcp_segment(self, data):
        """Parse TCP segment"""
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x1FF
        
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1
        
        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
    def parse_udp_segment(self, data):
        """Parse UDP segment"""
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, length, data[8:]
    
    def parse_icmp_packet(self, data):
        """Parse ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]
    
    def display_packet_info(self, timestamp, src_ip, dest_ip, protocol, info, payload=None):
        """Display formatted packet information"""
        print(f"\n{'='*60}")
        print(f"Timestamp: {timestamp}")
        print(f"Source:      {src_ip}")
        print(f"Destination: {dest_ip}")
        print(f"Protocol:    {protocol}")
        print(f"Info:        {info}")
        
        if payload:
            print(f"\nPayload ({len(payload)} bytes):")
            print(f"{self.mask_sensitive_data(payload)}")
    
    def start_sniffing(self):
        """Start packet capture"""
        iface = self.get_interface()
        if not iface:
            print("No network interface found!")
            return
        
        print(f"\nStarting capture on interface: {iface}")
        print(f"Filter: {self.protocol_filter or 'ALL'}")
        print(f"Packet limit: {self.packet_count} (0 = unlimited)")
        print("Press Ctrl+C to stop\n")
        
        try:
            # Create socket and bind to interface
            conn = self.create_socket()
            if iface:
                conn.bind((iface, 0))
        except Exception as e:
            print(f"Error binding to interface: {e}")
            return
        
        while True:
            if self.packet_count > 0 and self.captured_count >= self.packet_count:
                print(f"\nCaptured {self.captured_count} packets. Stopping...")
                break
            
            try:
                raw_data, addr = conn.recvfrom(65535)
                self.process_packet(raw_data)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error receiving packet: {e}")
                continue
    
    def process_packet(self, data):
        """Process captured packet"""
        dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(data)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Ethernet protocol types
        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src_ip, dest_ip, data = self.parse_ip_packet(data)
            
            # Apply protocol filter
            if self.protocol_filter:
                protocol_name = self.get_protocol_name(proto)
                if self.protocol_filter not in protocol_name.lower():
                    return
            
            info = f"IPv{version}, Header: {header_length} bytes, TTL: {ttl}"
            
            # TCP
            if proto == 6:
                src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, payload = self.parse_tcp_segment(data)
                protocol = "TCP"
                info = f"TCP {src_ip}:{src_port} → {dest_ip}:{dest_port} | "
                info += f"Flags: "
                flags = []
                if urg: flags.append("URG")
                if ack_flag: flags.append("ACK")
                if psh: flags.append("PSH")
                if rst: flags.append("RST")
                if syn: flags.append("SYN")
                if fin: flags.append("FIN")
                info += '/'.join(flags) if flags else "None"
                info += f" | Seq: {seq}, Ack: {ack}"
                
                self.display_packet_info(timestamp, f"{src_ip}:{src_port}", 
                                       f"{dest_ip}:{dest_port}", protocol, info, payload)
            
            # UDP
            elif proto == 17:
                src_port, dest_port, length, payload = self.parse_udp_segment(data)
                protocol = "UDP"
                info = f"UDP {src_ip}:{src_port} → {dest_ip}:{dest_port} | Length: {length}"
                self.display_packet_info(timestamp, f"{src_ip}:{src_port}", 
                                       f"{dest_ip}:{dest_port}", protocol, info, payload)
            
            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, payload = self.parse_icmp_packet(data)
                protocol = "ICMP"
                info = f"ICMP Type: {icmp_type}, Code: {code}, Checksum: {checksum}"
                self.display_packet_info(timestamp, src_ip, dest_ip, protocol, info, payload)
            
            # Other IP protocols
            else:
                protocol = self.get_protocol_name(proto)
                info = f"{protocol} Protocol"
                self.display_packet_info(timestamp, src_ip, dest_ip, protocol, info, data[:100])
            
            self.captured_count += 1
        
        # ARP or other Ethernet protocols
        elif eth_proto == 2054:  # ARP
            if not self.protocol_filter or self.protocol_filter == 'arp':
                protocol = "ARP"
                info = f"ARP {src_mac} → {dest_mac}"
                self.display_packet_info(timestamp, src_mac, dest_mac, protocol, info)
                self.captured_count += 1
        
        # Other Ethernet frames
        else:
            if not self.protocol_filter:
                protocol = f"Ethernet 0x{eth_proto:04x}"
                info = f"Frame {src_mac} → {dest_mac}"
                self.display_packet_info(timestamp, src_mac, dest_mac, protocol, info)
                self.captured_count += 1
    
    def get_protocol_name(self, proto_num):
        """Get protocol name from number"""
        protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP",
            2: "IGMP", 88: "EIGRP", 89: "OSPF"
        }
        return protocols.get(proto_num, f"Unknown ({proto_num})")

def main():
    parser = argparse.ArgumentParser(
        description="Educational Packet Sniffer - For authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Sniff all protocols
  %(prog)s --interface eth0   # Sniff on specific interface
  %(prog)s --filter tcp       # Sniff only TCP packets
  %(prog)s --count 20         # Capture 20 packets and exit
  
WARNING: This tool is for educational purposes only.
         Only use on networks you own or have permission to monitor.
        """
    )
    
    parser.add_argument("--interface", "-i", help="Network interface to sniff on")
    parser.add_argument("--filter", "-f", help="Filter by protocol (tcp, udp, icmp, arp)")
    parser.add_argument("--count", "-c", type=int, default=50, 
                       help="Number of packets to capture (0 = unlimited)")
    
    args = parser.parse_args()
    
    # Display ethical warning
    display_ethical_warning()
    
    # Create and start sniffer
    sniffer = EthicalPacketSniffer(
        interface=args.interface,
        protocol_filter=args.filter,
        packet_count=args.count
    )
    
    sniffer.start_sniffing()

if __name__ == "__main__":
    # Check if running with sudo/root
    if os.geteuid() != 0:
        print("This program requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    main()
