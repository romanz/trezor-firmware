# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TezosDelegationOp(p.MessageType):

    def __init__(
        self,
        *,
        source: bytes,
        fee: int,
        counter: int,
        gas_limit: int,
        storage_limit: int,
        delegate: bytes,
    ) -> None:
        self.source = source
        self.fee = fee
        self.counter = counter
        self.gas_limit = gas_limit
        self.storage_limit = storage_limit
        self.delegate = delegate

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            7: ('source', p.BytesType, p.FLAG_REQUIRED),
            2: ('fee', p.UVarintType, p.FLAG_REQUIRED),
            3: ('counter', p.UVarintType, p.FLAG_REQUIRED),
            4: ('gas_limit', p.UVarintType, p.FLAG_REQUIRED),
            5: ('storage_limit', p.UVarintType, p.FLAG_REQUIRED),
            6: ('delegate', p.BytesType, p.FLAG_REQUIRED),
        }
