# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class TxConfidentialValue(p.MessageType):

    def __init__(
        self,
        value: bytes = None,
        asset: bytes = None,
        nonce: bytes = None,
    ) -> None:
        self.value = value
        self.asset = asset
        self.nonce = nonce

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('value', p.BytesType, 0),  # required
            2: ('asset', p.BytesType, 0),  # required
            3: ('nonce', p.BytesType, 0),
        }
