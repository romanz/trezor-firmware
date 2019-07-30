# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .MultisigRedeemScriptType import MultisigRedeemScriptType

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
        EnumTypeInputScriptType = Literal[0, 1, 2, 3, 4]
    except ImportError:
        pass


class GetAddress(p.MessageType):
    MESSAGE_WIRE_TYPE = 29

    def __init__(
        self,
        address_n: List[int] = None,
        coin_name: str = None,
        show_display: bool = None,
        multisig: MultisigRedeemScriptType = None,
        script_type: EnumTypeInputScriptType = None,
        confidential: bool = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.coin_name = coin_name
        self.show_display = show_display
        self.multisig = multisig
        self.script_type = script_type
        self.confidential = confidential

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('coin_name', p.UnicodeType, 0),  # default=Bitcoin
            3: ('show_display', p.BoolType, 0),
            4: ('multisig', MultisigRedeemScriptType, 0),
            5: ('script_type', p.EnumType("InputScriptType", (0, 1, 2, 3, 4)), 0),  # default=SPENDADDRESS
            6: ('confidential', p.BoolType, 0),
        }
