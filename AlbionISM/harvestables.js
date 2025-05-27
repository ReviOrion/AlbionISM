
import base64
import math
from typing import List


class Harvestable:
    """
    Represents a single harvestable resource in the game world.
    """

    def __init__(self, id, type_, tier, pos_x, pos_y, charges, size):
        self.id = id                      # Unique identifier
        self.type = type_                # Type of resource (e.g., wood, ore)
        self.tier = tier                 # Tier/level of the resource
        self.pos_x = pos_x               # X coordinate of the resource
        self.pos_y = pos_y               # Y coordinate of the resource
        self.h_x = 0                     # Placeholder for harvesting X (unused)
        self.h_y = 0                     # Placeholder for harvesting Y (unused)
        self.charges = charges           # Number of charges or uses
        self.size = size                 # Total amount or size of the resource

    def set_charges(self, charges):
        """
        Updates the number of charges for the resource.
        """
        self.charges = charges


class HarvestablesHandler:
    """
    Manages all harvestable resources currently active in the game.
    """

    def __init__(self):
        self.harvestable_list: List[Harvestable] = []  # List of all harvestable objects

    def add_harvestable(self, id, type_, tier, pos_x, pos_y, charges, size):
        """
        Adds a new harvestable or updates the charges if it already exists.
        """
        h = Harvestable(id, type_, tier, pos_x, pos_y, charges, size)
        index = next((i for i, item in enumerate(self.harvestable_list) if item.id == h.id), -1)

        if index == -1:
            self.harvestable_list.append(h)  # Add new harvestable
        else:
            self.harvestable_list[index].set_charges(charges)  # Update existing charges

    def harvest_finished(self, parameters):
        """
        Called when harvesting is finished; updates the resource size.
        """
        id = parameters[3]
        count = parameters[5]
        self.update_harvestable(id, count)

    def new_harvestable_object(self, id, parameters):
        """
        Creates a new harvestable object from a structured parameter list.
        """
        type_ = parameters[5]
        tier = parameters[7]
        location = parameters[8]

        enchant = 0
        size = 0

        if len(parameters) > 10:
            size = parameters[10]

        if len(parameters) > 11:
            enchant = parameters[11]

        self.add_harvestable(id, type_, tier, location[0], location[1], enchant, size)

    def base64_to_array_buffer(self, base64_string):
        """
        Converts a Base64 string to a byte array.
        """
        return bytearray(base64.b64decode(base64_string))

    def new_simple_harvestable_object(self, parameters):
        """
        Processes a batch of simple harvestable objects from a compact format.
        """
        a0 = parameters[0]
        if not a0:
            return

        a1 = parameters[1]["data"]
        a2 = parameters[2]["data"]
        a3 = parameters[3]
        a4 = parameters[4]["data"]

        for i in range(len(a0)):
            id = a0[i]
            type_ = a1[i]
            tier = a2[i]
            pos_x = a3[i * 2]
            pos_y = a3[i * 2 + 1]
            count = a4[i]

            self.add_harvestable(id, type_, tier, pos_x, pos_y, 0, count)

    def remove_not_in_range(self, lp_x, lp_y):
        """
        Removes harvestables that are more than 80 units away from a given point.
        """
        self.harvestable_list = [
            x for x in self.harvestable_list
            if self.calculate_distance(lp_x, lp_y, x.pos_x, x.pos_y) <= 80
        ]
        self.harvestable_list = [item for item in self.harvestable_list if item.size is not None]

    def calculate_distance(self, lp_x, lp_y, pos_x, pos_y):
        """
        Calculates 2D Euclidean distance between two points.
        """
        delta_x = lp_x - pos_x
        delta_y = lp_y - pos_y
        return math.sqrt(delta_x ** 2 + delta_y ** 2)

    def remove_harvestable(self, id):
        """
        Removes a harvestable resource from the list by its ID.
        """
        self.harvestable_list = [x for x in self.harvestable_list if x.id != id]

    def get_harvestable_list(self):
        """
        Returns a copy of the current list of harvestables.
        """
        return list(self.harvestable_list)

    def update_harvestable(self, harvestable_id, count):
        """
        Reduces the size of a harvestable by the specified count.
        """
        harvestable = next((h for h in self.harvestable_list if h.id == harvestable_id), None)
        if harvestable:
            harvestable.size -= count

    def clear(self):
        """
        Clears all harvestables from the list.
        """
        self.harvestable_list.clear()
