# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TxRequestDetailsType(p.MessageType):

    def __init__(
        self,
        *,
        request_index: Optional[int] = None,
        tx_hash: Optional[bytes] = None,
        extra_data_len: Optional[int] = None,
        extra_data_offset: Optional[int] = None,
    ) -> None:
        self.request_index = request_index
        self.tx_hash = tx_hash
        self.extra_data_len = extra_data_len
        self.extra_data_offset = extra_data_offset

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('request_index', p.UVarintType, None),
            2: ('tx_hash', p.BytesType, None),
            3: ('extra_data_len', p.UVarintType, None),
            4: ('extra_data_offset', p.UVarintType, None),
        }
