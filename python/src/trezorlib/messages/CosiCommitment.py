# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class CosiCommitment(p.MessageType):
    MESSAGE_WIRE_TYPE = 72

    def __init__(
        self,
        *,
        commitment: Optional[bytes] = None,
        pubkey: Optional[bytes] = None,
    ) -> None:
        self.commitment = commitment
        self.pubkey = pubkey

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('commitment', p.BytesType, None),
            2: ('pubkey', p.BytesType, None),
        }
