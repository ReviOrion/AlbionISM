from typing import Any, Dict, Optional

class OperationRequest:
    def __init__(self, code: int, parameters: Dict[int, Any]):
        self.code = code
        self.parameters = parameters

class OperationResponse:
    def __init__(self, code: int, parameters: Dict[int, Any], return_code: int, signal_code: Optional[str]):
        self.code = code
        self.parameters = {k:v for k,v in parameters.items()}
        self.return_code = return_code
        self.signal_code = signal_code

class EventData:
    def __init__(self, code: int, parameters: Dict[int, Any]):
        self.code = code
        self.parameters = parameters