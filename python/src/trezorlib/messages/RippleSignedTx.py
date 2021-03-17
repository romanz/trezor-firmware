# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class RippleSignedTx(p.MessageType):
    MESSAGE_WIRE_TYPE = 403

    def __init__(
        self,
        *,
        signature: bytes,
        serialized_tx: bytes,
    ) -> None:
        self.signature = signature
        self.serialized_tx = serialized_tx

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('signature', p.BytesType, p.FLAG_REQUIRED),
            2: ('serialized_tx', p.BytesType, p.FLAG_REQUIRED),
        }
