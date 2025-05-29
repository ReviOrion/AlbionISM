from typing import Any, Dict, Optional
import uuid

def load_item_map() -> dict[int, dict[str, str]]:
    filepath = "photon_parser\parser_data\items.txt"
    item_map = {}
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if ':' not in line:
                continue
            parts = [p.strip() for p in line.strip().split(':')]
            if len(parts) < 3:
                continue
            try:
                item_id = int(parts[0])
                internal_name = parts[1]
                friendly_name = parts[2]
                item_map[item_id] = {
                    "internal_name": internal_name,
                    "friendly_name": friendly_name
                }
            except ValueError:
                continue
    return item_map


def search_item_map(item_map: dict[int, dict[str, str]], *, by_id=None, by_internal_name=None, by_friendly_name=None):
    if by_id is not None:
        # Search by ID (fast dict lookup)
        return item_map.get(by_id)

    # Otherwise, search by internal or friendly name (slow linear search)
    for item_id, info in item_map.items():
        if by_internal_name is not None and info["internal_name"] == by_internal_name:
            return {item_id: info}
        if by_friendly_name is not None and info["friendly_name"] == by_friendly_name:
            return {item_id: info}
    return None

def load_world_map() -> dict[int | str, dict[str, str]]:
    filepath = "photon_parser\parser_data\world.txt"
    world_map = {}

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if ':' not in line:
                continue

            try:
                key_part, name_part = line.strip().split(':', 1)
                key = key_part.strip()
                location_name = name_part.strip()

                # Try to convert key to int; if it fails, leave as string
                try:
                    key = int(key)
                except ValueError:
                    pass

                world_map[key] = {"location_name": location_name}
            except ValueError:
                continue
    return world_map


def search_world_map(world_map, *, by_id=None, by_location_name=None):
    if by_id is not None:
        # First, try raw input
        if by_id in world_map:
            return world_map[by_id]

        # If it's a string like "(1214)", clean and try int
        if isinstance(by_id, str):
            cleaned = by_id.strip().strip('()')
            try:
                alt_key = int(cleaned)
                if alt_key in world_map:
                    return world_map[alt_key]
            except ValueError:
                pass

    if by_location_name is not None:
        for world_id, info in world_map.items():
            if info["location_name"] == by_location_name:
                return {world_id: info}

    return None

class packet_30_newEquipmentItem:

    def __init__(self):
        self.object_id: str = ""
        self.item_info = {}
        self.quantity: int = 0
        self.estCost: int = 0
        self.craftedByPlayer: str = ""
        self.quality: str = ""
        self.durability: int = 0
        self.active_spells = []
        self.passive: int = 0


    def try_deserialize(self, parameters: Dict[int, Any]):
        
        self.object_id = parameters.get(0,0)
        self.item_id = search_item_map(load_item_map(),by_id=parameters.get(1))
        self.quantity = parameters.get(2,0)
        self.estCost = parameters.get(4, 0) / 10000 if parameters.get(4, 0) > 0 else 0
        self.craftedByPlayer = parameters.get(5,"")
        QualityType = {1:"NORMAL", 2:"GOOD", 3:"OUTSTANDING", 4:"EXCELLENT", 5:"MASTERPIECE"}
        self.quality = QualityType[parameters.get(6,0)]
        self.durability = parameters.get(7, 0) / 10000 if parameters.get(7, 0) > 0 else 0
        self.active_spells = [active_spell for active_spell in parameters[8] if active_spell != 0]
        self.passive = parameters.get(9,0)
    
    def to_dict(self):
        return{
            
        }

    def pretty_print(self):
        print(f"Object ID: {self.object_id}, Item ID: {self.item_id} , Quantity: {self.quantity} , Estimated Cost: {self.estCost} , Crafted by Player: {self.craftedByPlayer} , Quality: {self.quality} , Durability: {self.durability} , Active spells: {self.active_spells} , Passive: {self.passive}")

class packet_100_detachItemContainer:
    def __init__(self):
        self.container_id: str = ""
    
    def try_deserialize(self, parameters: Dict[int, Any]):
        if 0 in parameters:
            uuid_bytes = parameters[0]
            if isinstance(uuid_bytes, list) and len(uuid_bytes) == 16:
                # Convert list of bytes to bytes object, then to UUID string
                byte_array = bytes(uuid_bytes)
                self.container_id = str(uuid.UUID(bytes=byte_array))
            else:
                self.container_id = f"Invalid UUID data: {uuid_bytes}"
    
    def pretty_print(self):
        print(f"Container ID: {self.container_id}")

class packet_99_attachItemContainer:
    def __init__(self):
        self.object_id: str = ""
        self.UUID: str = ""
        self.container_id: str = ""
        self.slots: int = 0
        self.items = []

    def try_deserialize(self, parameters: Dict[int, Any]):
        """
        Deserialize packet data from parameters dictionary
        Args:
            parameters: Dictionary with integer keys and various value types
        """
        # Get object_id from key 0
        if 0 in parameters:
            self.object_id = parameters[0]
        
        if 2 in parameters:
            uuid_bytes = parameters[1]
            if isinstance(uuid_bytes, list) and len(uuid_bytes) == 16:
                # Convert list of bytes to bytes object, then to UUID string
                byte_array = bytes(uuid_bytes)
                self.container_id = str(uuid.UUID(bytes=byte_array))
            else:
                self.container_id = f"Invalid UUID data: {uuid_bytes}"
        
        # Get UUID from key 2 - it's a list of bytes that needs conversion
        if 1 in parameters:
            uuid_bytes = parameters[2]
            if isinstance(uuid_bytes, list) and len(uuid_bytes) == 16:
                # Convert list of bytes to bytes object, then to UUID string
                byte_array = bytes(uuid_bytes)
                self.UUID = str(uuid.UUID(bytes=byte_array))
            else:
                self.UUID = f"Invalid UUID data: {uuid_bytes}"
        
        if 4 in parameters:
            self.slots = parameters.get(4)
        
        if 3 in parameters:
            self.items=[item_id for item_id in parameters[3] if item_id != 0]

    
    def pretty_print(self):
        print(f"Object ID: {self.object_id}, Container ID: {self.container_id} , UUID: {self.UUID}, slots: {self.slots}, items: {self.items}")


class op_packet_35_ChangeCluster:
    def __init__(self):
        self.location_id: str = ""
        self.location: str = ""
        self.cluster: str = ""
        self.owner: str = ""
        self.raw_object_id: tuple = ()
    
    def try_deserialize(self, parameters: Dict[int, Any]):
        self.raw_object_id = parameters.get(0, 0)
        if isinstance(self.raw_object_id, tuple):
            self.location_id = self.raw_object_id[0]
            location_id = self.raw_object_id[0]
        else:
            self.location_id = self.raw_object_id
            location_id = self.raw_object_id
        self.location = search_world_map(load_world_map(),by_id=location_id)
        self.cluster = parameters.get(1)
        self.owner = parameters.get(2)
    
    def pretty_print(self):
        print(f"Location ID: {self.location_id}, location name: {self.location}, Cluster type: {self.cluster}, {self.raw_object_id[1]} , Owner: {self.owner}")

