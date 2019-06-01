from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED


def boot():
    ns = [["secp256k1", HARDENED | 10077]]
    wire.add(MessageType.LiquidBlindTx, __name__, "blind_tx", ns)
    wire.add(MessageType.LiquidUnblindOutput, __name__, "unblind_output", ns)
