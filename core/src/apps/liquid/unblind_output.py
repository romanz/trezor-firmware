from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidAmount import LiquidAmount

from . import blind


async def unblind_output(ctx, msg, keychain):
    return blind.unblind_output(blinded=msg.blinded,
                                ecdh_privkey=msg.ecdh_privkey)
