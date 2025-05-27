from typing import Any, Dict, Optional
import uuid

class packet_30_newEquipmentItem:

    def __init__(self):
        self.object_id: str = ""
        self.item_id: str = ""
        self.quantity: int = 0
        self.estCost: int = 0
        self.craftedByPlayer: str = ""
        self.quality: str = ""
        self.durability: int = 0
        self.active_spells = []
        self.passive: int = 0


    def try_deserialize(self, parameters: Dict[int, Any]):
        
        self.object_id = parameters.get(0,0)
        self.item_id = parameters.get(1,0)
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
