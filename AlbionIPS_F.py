import socket
import json
import threading
import platform
import time
import struct
from datetime import datetime
from collections import defaultdict, Counter

def local_ip():
    """Get local IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

class InventoryItem:
    """Represents an item found in inventory/storage data"""
    
    def __init__(self, data_dict):
        self.raw_data = data_dict
        # Extract common inventory fields if they exist
        self.item_id = data_dict.get('ItemTypeId', data_dict.get('ItemId', 'Unknown'))
        self.quantity = data_dict.get('Amount', data_dict.get('Count', 1))
        self.quality = data_dict.get('QualityLevel', data_dict.get('Quality', 0))
        self.enchantment = data_dict.get('EnchantmentLevel', data_dict.get('Enchant', 0))
        self.tier = data_dict.get('Tier', 0)
        
    def __str__(self):
        return f"Item(ID:{self.item_id}, Qty:{self.quantity}, T{self.tier}.{self.enchantment}@{self.quality})"

class InventoryData:
    """Container for organized inventory/storage data"""
    
    def __init__(self, logs, parsed_items, malformed, container_info=None):
        self.logs = logs[:]
        self.parsed_items = parsed_items[:]
        self.malformed = malformed[:]
        self.container_info = container_info or {}
        self.timestamp = datetime.now()
    
    def __len__(self):
        return len(self.parsed_items)
    
    def get_summary(self):
        """Get summary of inventory contents"""
        summary = {
            'total_items': len(self.parsed_items),
            'unique_items': len(set(item.item_id for item in self.parsed_items)),
            'total_quantity': sum(item.quantity for item in self.parsed_items),
            'malformed_packets': len(self.malformed),
            'timestamp': self.timestamp.isoformat()
        }
        
        # Count items by type
        item_counts = Counter(item.item_id for item in self.parsed_items)
        summary['most_common_items'] = item_counts.most_common(10)
        
        return summary
    
    def to_json(self):
        """Export data as JSON"""
        return json.dumps({
            'summary': self.get_summary(),
            'items': [item.raw_data for item in self.parsed_items],
            'malformed': self.malformed,
            'container_info': self.container_info
        }, indent=2, default=str)

class AlbionInventoryThread(threading.Thread):
    """Thread for sniffing Albion Online inventory/storage data"""
    
    def __init__(self):
        threading.Thread.__init__(self)
        
        # Known problematic strings that can corrupt data
        self.problems = ["'", "$", "QH", "?8", "H@", "ZP", "\\x00", "\\xff"]
        
        # Inventory-related keywords to look for
        self.inventory_keywords = [
            "Container", "Inventory", "Item", "Storage", "Chest", 
            "Bank", "Guild", "Personal", "Mount", "Equipment",
            "ItemTypeId", "ItemId", "Amount", "Count", "Quality",
            "Enchantment", "Tier", "Stack"
        ]
        
        # Thread state
        self.recording = False
        self.last_parsed = True
        self.logs = [""]
        self.parsed_items = []
        self.malformed = []
        self.container_events = []
        
        # Statistics
        self.total_packets = 0
        self.inventory_packets = 0
        self.start_time = None
        
        # Initialize socket
        self._setup_socket()
    
    def _setup_socket(self):
        """Setup raw socket for packet capture"""
        try:
            if platform.system() != "Windows":
                self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            else:
                # Windows setup
                self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW)
                self.sniffer.bind((local_ip(), 0))
                self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                
            print(f"Socket initialized successfully on {local_ip()}")
        except Exception as e:
            print(f"Socket setup error: {e}")
            print("Make sure to run as Administrator/root!")
            raise
    
    def run(self):
        """Main sniffing loop"""
        self.recording = True
        self.start_time = time.time()
        print("Starting Albion inventory packet capture...")
        print("Perform inventory actions now (open chests, move items, etc.)")
        
        while self.recording:
            try:
                # Receive packet data
                data, addr = self.sniffer.recvfrom(2048)
                self.total_packets += 1
                
                # Convert to string and clean
                data_str = str(data)
                for problem in self.problems:
                    data_str = data_str.replace(problem, "")
                
                # Look for inventory-related data
                if self._contains_inventory_keywords(data_str):
                    self.inventory_packets += 1
                    self._process_inventory_data(data_str)
                    
            except OSError as e:
                if self.recording:  # Only print if we're still supposed to be recording
                    print(f"Socket error: {e}")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                continue
        
        # Final parsing
        if not self.last_parsed:
            self.parse_data()
        
        print(f"\nCapture complete!")
        print(f"Total packets: {self.total_packets}")
        print(f"Inventory packets: {self.inventory_packets}")
        print(f"Duration: {time.time() - self.start_time:.1f}s")
    
    def _contains_inventory_keywords(self, data_str):
        """Check if data contains inventory-related keywords"""
        return any(keyword.lower() in data_str.lower() for keyword in self.inventory_keywords)
    
    def _process_inventory_data(self, data_str):
        """Process data that appears to contain inventory information"""
        # Look for JSON-like structures
        chunks = []
        
        # Split on common delimiters and look for JSON patterns
        potential_chunks = [s for s in data_str.split("\\") if len(s) > 5]
        
        for chunk in potential_chunks:
            # Look for JSON patterns
            if "{" in chunk or "Item" in chunk or "Container" in chunk:
                # Clean up the chunk
                if "{" in chunk:
                    json_start = chunk.find("{")
                    clean_chunk = chunk[json_start:]
                    chunks.append(clean_chunk)
                elif any(keyword in chunk for keyword in self.inventory_keywords):
                    chunks.append(chunk)
        
        # Process chunks
        for chunk in chunks:
            if "{" in chunk[:10]:  # New JSON object
                self.logs.append(chunk)
            elif self.logs and not chunk.startswith("b'"):  # Continuation
                self.logs[-1] += chunk
        
        self.last_parsed = False
    
    def parse_data(self):
        """Parse collected data into inventory items"""
        self.parsed_items = []
        self.malformed = []
        
        if not self.logs[0]:
            self.logs.pop(0)
        
        print(f"Parsing {len(self.logs)} log entries...")
        
        for i, log in enumerate(self.logs):
            try:
                # Try to parse as JSON first
                if "{" in log and "}" in log:
                    # Extract JSON part
                    json_start = log.find("{")
                    json_end = log.rfind("}") + 1
                    json_str = log[json_start:json_end]
                    
                    # Clean up common issues
                    json_str = json_str.replace("'", '"')  # Fix single quotes
                    json_str = json_str.replace('True', 'true').replace('False', 'false')
                    
                    try:
                        data_dict = json.loads(json_str)
                        # Check if this looks like inventory data
                        if self._is_inventory_data(data_dict):
                            item = InventoryItem(data_dict)
                            self.parsed_items.append(item)
                        else:
                            # Store as potential container/metadata
                            self.container_events.append(data_dict)
                    except json.JSONDecodeError:
                        # Try alternative parsing methods
                        alt_parsed = self._alternative_parse(log)
                        if alt_parsed:
                            self.parsed_items.extend(alt_parsed)
                        else:
                            self.malformed.append(log)
                else:
                    # Non-JSON inventory data
                    alt_parsed = self._alternative_parse(log)
                    if alt_parsed:
                        self.parsed_items.extend(alt_parsed)
                    else:
                        self.malformed.append(log)
                        
            except Exception as e:
                print(f"Parse error for log {i}: {e}")
                self.malformed.append(log)
        
        self.last_parsed = True
        print(f"Parsed {len(self.parsed_items)} items, {len(self.malformed)} malformed entries")
    
    def _is_inventory_data(self, data_dict):
        """Check if parsed data represents inventory items"""
        inventory_indicators = ['ItemTypeId', 'ItemId', 'Amount', 'Count', 'Quality', 'Tier']
        return any(key in data_dict for key in inventory_indicators)
    
    def _alternative_parse(self, log_entry):
        """Alternative parsing for non-JSON inventory data"""
        items = []
        
        # Look for patterns like "ItemId:12345 Amount:50 Quality:1"
        import re
        
        # Pattern for key:value pairs
        kv_pattern = r'(\w+):([^\s]+)'
        matches = re.findall(kv_pattern, log_entry)
        
        if matches:
            data_dict = {key: value for key, value in matches}
            # Convert numeric values
            for key in ['Amount', 'Count', 'Quality', 'Tier', 'ItemId', 'ItemTypeId']:
                if key in data_dict:
                    try:
                        data_dict[key] = int(data_dict[key])
                    except ValueError:
                        pass
            
            if self._is_inventory_data(data_dict):
                items.append(InventoryItem(data_dict))
        
        return items
    
    def get_data(self):
        """Get current inventory data"""
        if self.logs == [""]:
            return InventoryData([], [], [])
        
        if not self.last_parsed:
            self.parse_data()
        
        return InventoryData(self.logs, self.parsed_items, self.malformed, 
                           {'container_events': self.container_events})
    
    def stop(self):
        """Stop the sniffing thread"""
        self.recording = False
        try:
            self.sniffer.close()
        except:
            pass

class AlbionInventoryAnalyzer:
    """Main analyzer class for Albion inventory management"""
    
    def __init__(self):
        self.sniffer_thread = None
        self.current_data = None
    
    def start_capture(self, duration=120):
        """Start capturing inventory data"""
        print("=== Albion Online Inventory Analyzer ===")
        print(f"Capture duration: {duration} seconds")
        print("\nRecommended actions to perform:")
        print("1. Open your inventory")
        print("2. Open storage chests/banks")
        print("3. Move items between containers")
        print("4. Check guild storage")
        print("5. Open mount inventory")
        print("\nMake sure Albion Online is running!")
        
        input("Press Enter to start capture...")
        
        try:
            self.sniffer_thread = AlbionInventoryThread()
            self.sniffer_thread.start()
            
            # Let it run for specified duration
            time.sleep(duration)
            
            # Stop capture
            self.sniffer_thread.stop()
            self.sniffer_thread.join(timeout=5)
            
            # Get results
            self.current_data = self.sniffer_thread.get_data()
            self.generate_report()
            
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
            if self.sniffer_thread:
                self.sniffer_thread.stop()
        except Exception as e:
            print(f"Capture error: {e}")
            if self.sniffer_thread:
                self.sniffer_thread.stop()
    
    def generate_report(self):
        """Generate analysis report"""
        if not self.current_data:
            print("No data to analyze!")
            return
        
        print(f"\n=== Inventory Analysis Report ===")
        summary = self.current_data.get_summary()
        
        print(f"Capture completed at: {summary['timestamp']}")
        print(f"Total items found: {summary['total_items']}")
        print(f"Unique item types: {summary['unique_items']}")
        print(f"Total quantity: {summary['total_quantity']}")
        print(f"Malformed packets: {summary['malformed_packets']}")
        
        if summary['most_common_items']:
            print(f"\nMost common items:")
            for item_id, count in summary['most_common_items']:
                print(f"  {item_id}: {count} instances")
        
        # Show sample items
        if self.current_data.parsed_items:
            print(f"\nSample items found:")
            for item in self.current_data.parsed_items[:10]:
                print(f"  {item}")
        
        # Save data
        self.save_data()
    
    def save_data(self):
        """Save captured data to file"""
        if not self.current_data:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"albion_inventory_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                f.write(self.current_data.to_json())
            print(f"\nData saved to: {filename}")
        except Exception as e:
            print(f"Error saving data: {e}")

if __name__ == "__main__":
    print("Albion Online Inventory Management Tool")
    print("Based on existing Albion network sniffer")
    print("Make sure to run as Administrator on Windows!\n")
    
    analyzer = AlbionInventoryAnalyzer()
    
    try:
        duration = input("Capture duration in seconds (default 60): ").strip()
        duration = int(duration) if duration else 60
        analyzer.start_capture(duration)
    except ValueError:
        print("Invalid duration, using 60 seconds")
        analyzer.start_capture(60)
    except KeyboardInterrupt:
        print("\nExiting...")
