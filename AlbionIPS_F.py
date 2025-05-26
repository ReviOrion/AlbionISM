import threading
import time
import json
import os
from datetime import datetime
import csv
import sys

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not found! Please install it with: pip install scapy")

class AlbionPacketSniffer:
    def __init__(self, save_format='json', save_directory='captured_packets', interface=None):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required but not installed. Run: pip install scapy")
            
        self.running = False
        self.save_format = save_format.lower()
        self.save_directory = save_directory
        self.packets_captured = []
        self.session_start = None
        self.interface = interface
        
        # Create save directory if it doesn't exist
        if not os.path.exists(self.save_directory):
            os.makedirs(self.save_directory)
        
        # Albion Online related ports and information
        self.albion_ports = [5056, 5055, 5054, 5053, 5052]  # Common Albion ports
        self.albion_port_range = range(5050, 5065)  # Extended range
        self.packet_count = 0
        
        # Known Albion server IPs (you can extend this list)
        self.albion_server_patterns = [
            '5.45.187.',    # Some known Albion server ranges
            '5.45.186.',
            '5.45.185.',
            # Add more as you discover them
        ]
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = get_if_list()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces):
                try:
                    ip = get_if_addr(iface)
                    print(f"{i+1}. {iface} ({ip})")
                except:
                    print(f"{i+1}. {iface} (no IP)")
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []
    
    def select_interface(self):
        """Let user select network interface"""
        interfaces = self.get_available_interfaces()
        if not interfaces:
            print("No interfaces found, using default")
            return None
            
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interfaces)}) or press Enter for auto: ").strip()
                if not choice:
                    return None  # Auto-select
                
                choice = int(choice)
                if 1 <= choice <= len(interfaces):
                    selected = interfaces[choice - 1]
                    print(f"Selected interface: {selected}")
                    return selected
                else:
                    print("Invalid choice!")
            except ValueError:
                print("Please enter a number!")
    
    def is_albion_packet(self, packet):
        """Enhanced Albion packet detection"""
        try:
            if not packet.haslayer(IP):
                return False
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Check for TCP or UDP layers
            src_port = dst_port = None
            protocol = "Unknown"
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
            else:
                return False
            
            # Check if packet matches Albion criteria
            port_match = (src_port in self.albion_ports or 
                         dst_port in self.albion_ports or
                         src_port in self.albion_port_range or
                         dst_port in self.albion_port_range)
            
            # Check if IP matches known Albion server patterns
            ip_match = any(pattern in src_ip or pattern in dst_ip 
                          for pattern in self.albion_server_patterns)
            
            return port_match or ip_match
            
        except Exception as e:
            return False
    
    def extract_packet_info(self, packet):
        """Extract detailed information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'packet_size': len(packet)
            }
            
            # Extract IP information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dest_ip': ip_layer.dst,
                    'ip_version': ip_layer.version,
                    'ttl': ip_layer.ttl,
                    'ip_flags': ip_layer.flags
                })
            
            # Extract TCP information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp_layer.sport,
                    'dest_port': tcp_layer.dport,
                    'sequence': tcp_layer.seq,
                    'acknowledgment': tcp_layer.ack,
                    'tcp_flags': str(tcp_layer.flags),
                    'window_size': tcp_layer.window
                })
                
                # Extract payload
                if tcp_layer.payload:
                    payload_bytes = bytes(tcp_layer.payload)
                    packet_info.update({
                        'payload_size': len(payload_bytes),
                        'payload_hex': payload_bytes.hex(),
                        'payload_raw': payload_bytes[:100].hex() if len(payload_bytes) > 100 else payload_bytes.hex()  # First 100 bytes
                    })
                else:
                    packet_info.update({
                        'payload_size': 0,
                        'payload_hex': '',
                        'payload_raw': ''
                    })
            
            # Extract UDP information
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp_layer.sport,
                    'dest_port': udp_layer.dport,
                    'udp_length': udp_layer.len
                })
                
                # Extract payload
                if udp_layer.payload:
                    payload_bytes = bytes(udp_layer.payload)
                    packet_info.update({
                        'payload_size': len(payload_bytes),
                        'payload_hex': payload_bytes.hex(),
                        'payload_raw': payload_bytes[:100].hex() if len(payload_bytes) > 100 else payload_bytes.hex()
                    })
                else:
                    packet_info.update({
                        'payload_size': 0,
                        'payload_hex': '',
                        'payload_raw': ''
                    })
            
            # Add packet summary
            packet_info['packet_summary'] = packet.summary()
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            if not self.is_albion_packet(packet):
                return
            
            packet_info = self.extract_packet_info(packet)
            if not packet_info:
                return
            
            self.packets_captured.append(packet_info)
            self.packet_count += 1
            
            # Display packet info
            protocol = packet_info.get('protocol', 'Unknown')
            src = f"{packet_info.get('src_ip', 'Unknown')}:{packet_info.get('src_port', 'Unknown')}"
            dest = f"{packet_info.get('dest_ip', 'Unknown')}:{packet_info.get('dest_port', 'Unknown')}"
            payload_size = packet_info.get('payload_size', 0)
            
            print(f"[{self.packet_count}] {packet_info['timestamp'][:19]} | "
                  f"{protocol} | {src} -> {dest} | "
                  f"Size: {packet_info['packet_size']}B | Payload: {payload_size}B")
            
            # Auto-save every 25 packets
            if len(self.packets_captured) >= 25:
                self.save_current_session()
                self.packets_captured.clear()
                
        except Exception as e:
            print(f"Error handling packet: {e}")
    
    def save_current_session(self):
        """Save current session packets to file"""
        if not self.packets_captured:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        
        if self.save_format == 'json':
            self.save_as_json(timestamp)
        elif self.save_format == 'csv':
            self.save_as_csv(timestamp)
        elif self.save_format == 'txt':
            self.save_as_txt(timestamp)
        else:
            self.save_as_json(timestamp)
    
    def save_as_json(self, timestamp):
        """Save packets as JSON file"""
        filename = f"albion_packets_{timestamp}.json"
        filepath = os.path.join(self.save_directory, filename)
        
        session_data = {
            'session_info': {
                'start_time': self.session_start,
                'save_time': datetime.now().isoformat(),
                'total_packets_in_batch': len(self.packets_captured),
                'interface_used': self.interface,
                'capture_filter': 'Albion Online related traffic'
            },
            'packets': self.packets_captured
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(session_data, f, indent=2, default=str)
            print(f"[SAVED] {len(self.packets_captured)} packets to {filename}")
        except Exception as e:
            print(f"Error saving JSON: {e}")
    
    def save_as_csv(self, timestamp):
        """Save packets as CSV file"""
        filename = f"albion_packets_{timestamp}.csv"
        filepath = os.path.join(self.save_directory, filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if not self.packets_captured:
                    return
                
                # Get all possible field names
                all_fields = set()
                for packet in self.packets_captured:
                    all_fields.update(packet.keys())
                
                writer = csv.DictWriter(f, fieldnames=sorted(all_fields))
                writer.writeheader()
                
                for packet in self.packets_captured:
                    writer.writerow(packet)
            
            print(f"[SAVED] {len(self.packets_captured)} packets to {filename}")
        except Exception as e:
            print(f"Error saving CSV: {e}")
    
    def save_as_txt(self, timestamp):
        """Save packets as readable text file"""
        filename = f"albion_packets_{timestamp}.txt"
        filepath = os.path.join(self.save_directory, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Albion Online Packet Capture - Scapy Version\n")
                f.write(f"Session Start: {self.session_start}\n")
                f.write(f"Interface: {self.interface or 'Auto-selected'}\n")
                f.write(f"Batch Time: {datetime.now().isoformat()}\n")
                f.write(f"Packets in batch: {len(self.packets_captured)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, packet in enumerate(self.packets_captured, 1):
                    f.write(f"Packet #{i}\n")
                    f.write(f"Timestamp: {packet.get('timestamp', 'Unknown')}\n")
                    f.write(f"Protocol: {packet.get('protocol', 'Unknown')}\n")
                    f.write(f"Source: {packet.get('src_ip', 'Unknown')}:{packet.get('src_port', 'Unknown')}\n")
                    f.write(f"Destination: {packet.get('dest_ip', 'Unknown')}:{packet.get('dest_port', 'Unknown')}\n")
                    f.write(f"Packet Size: {packet.get('packet_size', 0)} bytes\n")
                    f.write(f"Payload Size: {packet.get('payload_size', 0)} bytes\n")
                    
                    if packet.get('sequence'):
                        f.write(f"TCP Sequence: {packet['sequence']}\n")
                    if packet.get('acknowledgment'):
                        f.write(f"TCP Acknowledgment: {packet['acknowledgment']}\n")
                    if packet.get('tcp_flags'):
                        f.write(f"TCP Flags: {packet['tcp_flags']}\n")
                    
                    if packet.get('payload_raw'):
                        f.write(f"Payload (first 100 bytes): {packet['payload_raw']}\n")
                    
                    f.write(f"Summary: {packet.get('packet_summary', 'N/A')}\n")
                    f.write("-" * 60 + "\n\n")
            
            print(f"[SAVED] {len(self.packets_captured)} packets to {filename}")
        except Exception as e:
            print(f"Error saving TXT: {e}")
    
    def start_capture(self):
        """Start packet capture using Scapy"""
        print(f"Starting Albion Online packet capture with Scapy...")
        print(f"Save format: {self.save_format.upper()}")
        print(f"Save directory: {self.save_directory}")
        print(f"Interface: {self.interface or 'Auto-selected'}")
        print("\nLooking for packets on ports:", list(self.albion_ports))
        print("Press Ctrl+C to stop capture\n")
        
        self.session_start = datetime.now().isoformat()
        self.running = True
        
        try:
            # Create capture filter for better performance
            capture_filter = f"tcp portrange 5050-5065 or udp portrange 5050-5065"
            
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=capture_filter,
                store=False,  # Don't store packets in memory
                stop_filter=lambda x: not self.running
            )
            
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.running = False
            
            # Save any remaining packets
            if self.packets_captured:
                self.save_current_session()
            
            print(f"\nCapture session ended.")
            print(f"Total packets captured: {self.packet_count}")
            print(f"Files saved in: {self.save_directory}")

def main():
    if not SCAPY_AVAILABLE:
        print("Please install Scapy first:")
        print("pip install scapy")
        return
    
    print("Albion Online Packet Sniffer - Scapy Edition")
    print("=" * 50)
    
    # Choose save format
    print("\nChoose save format:")
    print("1. JSON (structured data with full details)")
    print("2. CSV (spreadsheet compatible)")
    print("3. TXT (human readable)")
    
    while True:
        choice = input("Enter choice (1-3) or press Enter for JSON: ").strip()
        if choice == '1' or choice == '':
            save_format = 'json'
            break
        elif choice == '2':
            save_format = 'csv'
            break
        elif choice == '3':
            save_format = 'txt'
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
    
    # Optional: custom save directory
    save_dir = input("Enter save directory (or press Enter for 'captured_packets'): ").strip()
    if not save_dir:
        save_dir = 'captured_packets'
    
    # Create sniffer and let user select interface
    sniffer = AlbionPacketSniffer(save_format=save_format, save_directory=save_dir)
    
    print("\nInterface selection:")
    interface = sniffer.select_interface()
    sniffer.interface = interface
    
    print(f"\nStarting capture...")
    print("Note: You may need to run this as administrator for full packet access")
    
    # Start capture
    sniffer.start_capture()

if __name__ == "__main__":
    main()
