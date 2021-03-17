# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TxAckPrevExtraDataWrapper(p.MessageType):

    def __init__(
        self,
        *,
        extra_data_chunk: bytes,
    ) -> None:
        self.extra_data_chunk = extra_data_chunk

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            8: ('extra_data_chunk', p.BytesType, p.FLAG_REQUIRED),
        }
