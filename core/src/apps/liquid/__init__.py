from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED


def boot():
    CURVE = "secp256k1"
    ns = [
        # Allow Elements regtest for PKH and P2SH addresses
        [CURVE, HARDENED | 44, HARDENED | 1],
        [CURVE, HARDENED | 49, HARDENED | 1],
        # Allow blinding derivation key
        [CURVE, HARDENED | 77],
    ]
    wire.add(MessageType.LiquidGetBlindedAddress, __name__, "get_blinded_address", ns)
