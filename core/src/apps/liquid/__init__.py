from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED


def boot():
    ns = [["secp256k1", HARDENED | 44, HARDENED | 1776]]
    wire.add(MessageType.LiquidBlindOutput, __name__, "blind_output", ns)
    wire.add(MessageType.LiquidUnblindOutput, __name__, "unblind_output", ns)
