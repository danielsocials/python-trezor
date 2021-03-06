# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class ChangePin(p.MessageType):
    MESSAGE_WIRE_TYPE = 4

    def __init__(
        self,
        remove: bool = None,
    ) -> None:
        self.remove = remove

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('remove', p.BoolType, 0),
        }
