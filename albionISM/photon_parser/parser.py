import io

from crc_calculator import CrcCalculator
from protocol16_deserializer import Protocol16Deserializer
from protocol16_type import CommandType, MessageType
from segmented_packet import SegmentedPacket
from serializer import NumberSerializer

COMMAND_HEADER_LENGTH = 12
PHOTON_HEADER_LENGTH = 12


class PhotonParser:
    def __init__(self, on_eventdata, on_operation_request, on_operation_response):
        self.on_operation_request = on_operation_request
        self.on_operation_response = on_operation_response
        self.on_eventdata = on_eventdata
        self._pending_segments = {}

    def is_mcr_packet(self, payload):
        signatures = {
            b"\x4d\x43\x52\x48\x33\x31\x31\x30",
            b"\xe9\x71\x2d\xd5\x00\x01\x00\x00",
            b"\xe9\x71\x2d\xd5\x01\x01\x00\x00",
            b"\xe9\x71\x2d\xd5\x11\x01\x00\x00",
        }
        return payload[:8] in signatures

    def handle_payload(self, payload):
        if self.is_mcr_packet(payload):
            return

        payload = io.BytesIO(payload)
        if payload.getbuffer().nbytes < PHOTON_HEADER_LENGTH:
            return

        peer_id         = NumberSerializer.deserialize_short(payload)
        flags           = payload.read(1)[0]
        command_count   = payload.read(1)[0]
        timestamp       = NumberSerializer.deserialize_int(payload)
        _       = NumberSerializer.deserialize_int(payload) # Challenge

        is_encrypted    = flags == 1
        is_crc_enabled  = flags == 0xCC

        if is_crc_enabled:
            offset = payload.tell()
            payload.seek(0)
            crc = NumberSerializer.deserialize_int(payload)

            payload.seek(offset)
            payload = NumberSerializer.serialize_int(0, payload)

            if crc != CrcCalculator.calculate(payload, payload.getbuffer().nbytes):
                return

        for _ in range(command_count):
            self.handle_command(payload, peer_id, timestamp, is_encrypted)
            
    def handle_command(self, source: io.BytesIO, peer_id, timestamp: int, is_encrypted):
            if is_encrypted:
                print(timestamp, f"{peer_id} >> is_encrypted={is_encrypted}")
                return

            command_type    = source.read(1)[0]
            channel_id: int = source.read(1)[0]
            command_flags   = source.read(1)[0]

            source.read(1)
            command_length  = NumberSerializer.deserialize_int(source)
            sequence_number = NumberSerializer.deserialize_int(source)
            command_length -= COMMAND_HEADER_LENGTH

            if command_type == CommandType.Disconnect.value:
                return
            elif command_type == CommandType.SendUnreliable.value:
                source.read(4)
                command_length -= 4
                self.handle_send_reliable(timestamp, channel_id, source, command_length)
            elif command_type == CommandType.SendReliable.value:
                self.handle_send_reliable(timestamp, channel_id, source, command_length)
            elif command_type == CommandType.SendFragment.value:
                self.handle_send_fragment(timestamp, channel_id, source, command_length)
            else:
                source.read(command_length)
    
    def handle_send_reliable(self, timestamp: int, channel_id: int, source: io.BytesIO, command_length: int):
        source.read(1)
        command_length -= 1
        message_type = source.read(1)[0]
        command_length -= 1

        operation_length = command_length
        payload = io.BytesIO(source.read(operation_length))

        if message_type == MessageType.OperationRequest.value:
            rq_data = Protocol16Deserializer.deserialize_operation_request(payload)
            self.on_operation_request(rq_data, timestamp, channel_id)
        elif message_type == MessageType.OperationResponse.value:
            rs_data = Protocol16Deserializer.deserialize_operation_response(payload)
            self.on_operation_response(rs_data, timestamp, channel_id)
        elif message_type == MessageType.Event.value:
            event_data = Protocol16Deserializer.deserialize_event_data(payload)
            self.on_eventdata(event_data, timestamp, channel_id)
    
    def handle_send_fragment(self, timestamp, channel_id, source: io.BytesIO, command_length: int):
        start_sequence_number = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_count = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_number = NumberSerializer.deserialize_int(source)
        command_length -= 4
        total_length = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_offset = NumberSerializer.deserialize_int(source)
        command_length -= 4

        fragment_length = command_length

        self.handle_segmented_payload(
            timestamp, channel_id, 
            start_sequence_number,
            total_length,
            fragment_length,
            fragment_offset,
            source,
        )

    def handle_finished_segmented_packet(self, timestamp, channel_id, total_payload: bytearray):
        command_length = len(total_payload)
        self.handle_send_reliable(timestamp, channel_id, io.BytesIO(total_payload), command_length)
    
    def handle_segmented_payload(
        self,
        timestamp, channel_id, 
        start_sequence_number,
        total_length,
        fragment_length,
        fragment_offset,
        source,
    ):
        segmented_packet = self.get_segmented_packet(
            start_sequence_number, total_length
        )

        for i in range(fragment_length):
            segmented_packet.gh_Payload[fragment_offset + i] = source.read(1)[0]

        segmented_packet.bytes_written += fragment_length

        if segmented_packet.bytes_written >= segmented_packet.hw_Length:
            self._pending_segments.pop(start_sequence_number)
            self.handle_finished_segmented_packet(timestamp, channel_id, segmented_packet.gh_Payload)

    def get_segmented_packet(self, start_sequence_number, total_length):
        if start_sequence_number in self._pending_segments:
            return self._pending_segments[start_sequence_number]

        segmented_packet = SegmentedPacket(
            hw_Length=total_length, gh_Payload=bytearray(total_length)
        )

        self._pending_segments[start_sequence_number] = segmented_packet
        return segmented_packet