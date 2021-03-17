# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class SignedIdentity(p.MessageType):
    MESSAGE_WIRE_TYPE = 54

    def __init__(
        self,
        *,
        public_key: bytes,
        signature: bytes,
        address: Optional[str] = None,
    ) -> None:
        self.public_key = public_key
        self.signature = signature
        self.address = address

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address', p.UnicodeType, None),
            2: ('public_key', p.BytesType, p.FLAG_REQUIRED),
            3: ('signature', p.BytesType, p.FLAG_REQUIRED),
        }
