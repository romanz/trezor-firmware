# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class StellarAccountMergeOp(p.MessageType):
    MESSAGE_WIRE_TYPE = 218

    def __init__(
        self,
        *,
        source_account: Optional[str] = None,
        destination_account: Optional[str] = None,
    ) -> None:
        self.source_account = source_account
        self.destination_account = destination_account

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source_account', p.UnicodeType, None),
            2: ('destination_account', p.UnicodeType, None),
        }
