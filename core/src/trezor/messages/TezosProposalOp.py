# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TezosProposalOp(p.MessageType):

    def __init__(
        self,
        *,
        proposals: Optional[List[bytes]] = None,
        source: Optional[bytes] = None,
        period: Optional[int] = None,
    ) -> None:
        self.proposals = proposals if proposals is not None else []
        self.source = source
        self.period = period

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source', p.BytesType, None),
            2: ('period', p.UVarintType, None),
            4: ('proposals', p.BytesType, p.FLAG_REPEATED),
        }
