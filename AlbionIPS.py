from scapy.all import *
import json
import time
import collections
from datetime import datetime
import struct

class InventoryPacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.inventory_events = []
        self.game_servers = set()
        self.session_start = time.time()
        
    def analyze_packet(self, packet):
        """Analyze packets for inventory-related data"""
        if not packet.haslayer(IP):
            return
            
        timestamp = time.time() - self.session_start
        
        # Track game server IPs
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            self.game_servers.add(packet[IP].dst)
        
        # Look for packets with payload data
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            packet_info = {
                'timestamp': timestamp,
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'Other',
                'size': len(payload),
                'payload': payload,
                'hex_data': payload.hex()
            }
            
            # Add port information
            if packet.haslayer(TCP):
                packet_info['sport'] = packet[TCP].sport
                packet_info['dport'] = packet[TCP].dport
            elif packet.haslayer(UDP):
                packet_info['sport'] = packet[UDP].sport
                packet_info['dport'] = packet[UDP].dport
            
            # Analyze payload for potential inventory data
            self.analyze_payload(packet_info)
            self.packets.append(packet_info)
    
    def analyze_payload(self, packet_info):
        """Look for patterns that might indicate inventory data"""
        payload = packet_info['payload']
        
        # Look for common inventory-related patterns
        patterns_found = []
        
        # Check for repeated structures (common in inventory lists)
        if self.has_repeated_structures(payload):
            patterns_found.append('repeated_structures')
        
        # Check for potential item IDs (common patterns in game data)
        if self.has_potential_item_ids(payload):
            patterns_found.append('potential_item_ids')
        
        # Check for quantity-like data
        if self.has_quantity_patterns(payload):
            patterns_found.append('quantity_patterns')
        
        # Look for specific byte patterns that might indicate inventory operations
        if self.has_inventory_operation_patterns(payload):
            patterns_found.append('inventory_operations')
        
        if patterns_found:
            packet_info['inventory_patterns'] = patterns_found
            print(f"[{packet_info['timestamp']:.2f}s] Potential inventory packet: {patterns_found} ({len(payload)} bytes)")
    
    def has_repeated_structures(self, payload):
        """Check if payload has repeated byte patterns (common in item lists)"""
        if len(payload) < 32:  # Too small for meaningful structures
            return False
        
        # Look for repeating patterns of various sizes
        for pattern_size in [4, 8, 12, 16, 20]:
            if len(payload) >= pattern_size * 3:  # At least 3 repetitions
                for start in range(0, len(payload) - pattern_size * 2, pattern_size):
                    pattern = payload[start:start + pattern_size]
                    # Check if this pattern repeats
                    next_occurrence = payload.find(pattern, start + pattern_size)
                    if next_occurrence == start + pattern_size:
                        return True
        return False
    
    def has_potential_item_ids(self, payload):
        """Look for patterns that might be item IDs or similar identifiers"""
        if len(payload) < 8:
            return False
        
        # Look for 32-bit integers that might be item IDs
        for i in range(0, len(payload) - 4, 4):
            try:
                # Try both little and big endian
                val_le = struct.unpack('<I', payload[i:i+4])[0]
                val_be = struct.unpack('>I', payload[i:i+4])[0]
                
                # Item IDs often fall in reasonable ranges
                if (1000 <= val_le <= 999999) or (1000 <= val_be <= 999999):
                    return True
            except:
                continue
        return False
    
    def has_quantity_patterns(self, payload):
        """Look for small integers that might represent quantities"""
        if len(payload) < 4:
            return False
        
        small_int_count = 0
        for i in range(0, len(payload) - 2, 2):
            try:
                # Check for small 16-bit integers (common for quantities)
                val = struct.unpack('<H', payload[i:i+2])[0]
                if 1 <= val <= 9999:  # Reasonable quantity range
                    small_int_count += 1
            except:
                continue
        
        # If we find several small integers, might be quantities
        return small_int_count >= 3
    
    def has_inventory_operation_patterns(self, payload):
        """Look for specific patterns that might indicate inventory operations"""
        # Look for common operation codes or headers
        if len(payload) >= 4:
            # Check first few bytes for operation codes
            first_bytes = payload[:4]
            
            # These are hypothetical patterns - you'd refine based on actual data
            common_patterns = [
                b'\x01\x00\x00\x00',  # Possible operation codes
                b'\x02\x00\x00\x00',
                b'\x03\x00\x00\x00',
                b'\xFF\xFF\xFF\xFF',  # Possible markers
            ]
            
            return any(pattern in payload for pattern in common_patterns)
        return False
    
    def identify_albion_traffic(self):
        """First identify Albion Online's network traffic patterns"""
        print("=== Albion Online Traffic Identification ===")
        print("Please start Albion Online now if not already running...")
        input("Press Enter when the game is running and you're logged in...")
        
        print("\nPhase 1: Identifying Albion traffic patterns...")
        print("Capturing network activity for 30 seconds...")
        print("Please perform some basic actions in game (move around, open inventory, etc.)")
        
        temp_packets = []
        
        def temp_handler(pkt):
            if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                temp_packets.append(pkt)
        
        sniff(timeout=30, prn=temp_handler)
        
        # Analyze captured traffic to identify game servers
        print(f"\nAnalyzing {len(temp_packets)} packets...")
        
        # Count packets by destination and port
        traffic_analysis = collections.defaultdict(lambda: {'tcp_ports': set(), 'udp_ports': set(), 'count': 0})
        
        for pkt in temp_packets:
            dst_ip = pkt[IP].dst
            traffic_analysis[dst_ip]['count'] += 1
            
            if pkt.haslayer(TCP):
                traffic_analysis[dst_ip]['tcp_ports'].add(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                traffic_analysis[dst_ip]['udp_ports'].add(pkt[UDP].dport)
        
        # Find most active destinations (likely game servers)
        top_destinations = sorted(traffic_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
        
        print("\nTop network destinations (potential game servers):")
        albion_servers = []
        
        for i, (ip, data) in enumerate(top_destinations[:10]):
            tcp_ports = list(data['tcp_ports'])[:5]  # Show first 5 ports
            udp_ports = list(data['udp_ports'])[:5]
            
            print(f"{i+1}. {ip} - {data['count']} packets")
            if tcp_ports:
                print(f"   TCP ports: {tcp_ports}")
            if udp_ports:
                print(f"   UDP ports: {udp_ports}")
            
            # Heuristic: Game servers usually have consistent traffic and specific port patterns
            if data['count'] > 10:  # Reasonable amount of traffic
                albion_servers.append({
                    'ip': ip,
                    'tcp_ports': tcp_ports,
                    'udp_ports': udp_ports,
                    'packet_count': data['count']
                })
        
        return albion_servers
    
    def start_inventory_capture(self, duration=300, albion_servers=None):
        """Start capturing packets specifically looking for inventory data"""
        print(f"\n=== Inventory Packet Analyzer ===")
        
        if not albion_servers:
            albion_servers = self.identify_albion_traffic()
        
        if not albion_servers:
            print("No Albion servers identified. Proceeding with general capture...")
            sniff(timeout=duration, prn=self.analyze_packet)
            self.generate_inventory_report()
            return
        
        # Build filter for Albion traffic
        filters = []
        print(f"\nTargeting {len(albion_servers)} potential Albion servers:")
        
        for server in albion_servers[:3]:  # Focus on top 3 servers
            ip = server['ip']
            print(f"  {ip} ({server['packet_count']} packets)")
            
            # Create filters for this server's ports
            server_filters = [f"host {ip}"]
            
            # Add specific port filters if we identified common ports
            if server['tcp_ports']:
                common_tcp = server['tcp_ports'][:3]  # Use top 3 TCP ports
                for port in common_tcp:
                    server_filters.append(f"(host {ip} and tcp port {port})")
            
            if server['udp_ports']:
                common_udp = server['udp_ports'][:3]  # Use top 3 UDP ports
                for port in common_udp:
                    server_filters.append(f"(host {ip} and udp port {port})")
            
            filters.extend(server_filters)
        
        # Combine all filters
        combined_filter = " or ".join(filters[:10])  # Limit to avoid overly complex filter
        print(f"\nUsing filter: {combined_filter[:100]}...")
        
        print(f"\nStarting focused capture for {duration} seconds...")
        print("Recommended test sequence:")
        print("1. Open your inventory/chests")
        print("2. Move some items around")
        print("3. Check item quantities")
        print("4. Open/close storage containers")
        print("5. Perform trades or market operations")
        print("\nCapturing now...\n")
        
        try:
            sniff(filter=combined_filter, timeout=duration, prn=self.analyze_packet)
        except Exception as e:
            print(f"Filter error: {e}")
            print("Falling back to unfiltered capture...")
            sniff(timeout=duration, prn=self.analyze_packet)
        
        self.generate_inventory_report()
    
    def generate_inventory_report(self):
        """Generate a detailed report focusing on potential inventory data"""
        print(f"\n=== Inventory Analysis Report ===")
        print(f"Capture duration: {time.time() - self.session_start:.1f} seconds")
        print(f"Total packets analyzed: {len(self.packets)}")
        
        # Filter packets with inventory patterns
        inventory_packets = [p for p in self.packets if 'inventory_patterns' in p]
        print(f"Packets with inventory patterns: {len(inventory_packets)}")
        
        if not inventory_packets:
            print("No obvious inventory patterns detected.")
            print("This could mean:")
            print("- Inventory data is encrypted")
            print("- Data is compressed")
            print("- Different packet structure than expected")
            print("- Need to perform more varied inventory actions")
            return
        
        # Analyze inventory packet patterns
        print(f"\nInventory Pattern Analysis:")
        all_patterns = []
        for pkt in inventory_packets:
            all_patterns.extend(pkt['inventory_patterns'])
        
        pattern_counts = collections.Counter(all_patterns)
        for pattern, count in pattern_counts.items():
            print(f"  {pattern}: {count} packets")
        
        # Show some example packets
        print(f"\nSample Inventory Packets:")
        for i, pkt in enumerate(inventory_packets[:5]):
            print(f"\nPacket {i+1}:")
            print(f"  Time: {pkt['timestamp']:.2f}s")
            print(f"  Size: {pkt['size']} bytes")
            print(f"  Patterns: {pkt['inventory_patterns']}")
            print(f"  Hex preview: {pkt['hex_data'][:64]}...")
        
        # Timing analysis
        if len(inventory_packets) > 1:
            times = [p['timestamp'] for p in inventory_packets]
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            avg_interval = sum(intervals) / len(intervals)
            print(f"\nTiming Analysis:")
            print(f"  Average interval between inventory packets: {avg_interval:.2f}s")
            print(f"  Min interval: {min(intervals):.2f}s")
            print(f"  Max interval: {max(intervals):.2f}s")
        
        self.save_inventory_data()
    
    def save_inventory_data(self):
        """Save captured inventory data for further analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"inventory_capture_{timestamp}.json"
        
        # Prepare data for saving (convert bytes to hex strings)
        save_data = []
        for pkt in self.packets:
            if 'inventory_patterns' in pkt:
                pkt_copy = pkt.copy()
                pkt_copy['payload'] = pkt_copy['payload'].hex()  # Convert bytes to hex string
                save_data.append(pkt_copy)
        
        try:
            with open(filename, 'w') as f:
                json.dump(save_data, f, indent=2)
            print(f"\nInventory data saved to: {filename}")
            print("You can analyze this data further or use it to understand packet structures.")
        except Exception as e:
            print(f"Error saving data: {e}")

# Quick Albion port discovery script
def quick_albion_port_discovery():
    """Quick script to find Albion's commonly used ports"""
    print("=== Quick Albion Port Discovery ===")
    print("This will help identify common ports used by Albion Online")
    print("Make sure Albion is running and you're logged in!")
    input("Press Enter to start 15-second capture...")
    
    port_usage = collections.defaultdict(int)
    
    def port_analyzer(pkt):
        if pkt.haslayer(TCP):
            port_usage[f"TCP-{pkt[TCP].dport}"] += 1
        elif pkt.haslayer(UDP):
            port_usage[f"UDP-{pkt[UDP].dport}"] += 1
    
    sniff(timeout=15, prn=port_analyzer)
    
    print("\nMost used ports (likely Albion traffic):")
    for port, count in sorted(port_usage.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {port}: {count} packets")
    
    return port_usage

# Usage example
if __name__ == "__main__":
    print("Albion Online Network Analysis Tool")
    print("Make sure to run as Administrator on Windows!\n")
    
    print("Choose analysis mode:")
    print("1. Quick port discovery")
    print("2. Full inventory packet analysis")
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        quick_albion_port_discovery()
    else:
        analyzer = InventoryPacketAnalyzer()
        print("\nInventory Packet Analyzer for Storage Management")
        print("This tool will help identify packets containing inventory/chest data\n")
        
        # You can adjust the capture duration
        analyzer.start_inventory_capture(duration=120)  # 2 minutes of capture
