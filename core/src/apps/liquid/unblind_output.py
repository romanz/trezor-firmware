import gc

from trezor.crypto import hashlib, hmac
from trezor.crypto.curve import secp256k1_zkp
from trezor.messages.LiquidAmount import LiquidAmount
from trezor.messages.MessageType import LiquidUnblindOutput

from . import blind

from apps.common import HARDENED, seed


async def unblind_output(ctx, msg, keychain):
    gc.collect()
    context = secp256k1_zkp.Context()
    # NOTE: we can reuse {range,surjection}-proof buffer for message recovering
    message_buffer = secp256k1_zkp.allocate_proof_buffer()

    ecdh_privkey = msg.ecdh_privkey
    if not ecdh_privkey:
        master_blinding_key = (
            msg.master_blinding_key
            or seed.derive_slip21_node_without_passphrase([b"SLIP-0077"]).key()
        )
        ecdh_privkey = seed.derive_blinding_private_key(
            master_blinding_key=master_blinding_key, script=msg.blinded.script_pubkey
        )

    return blind.unblind_output(
        context=context,
        blinded=msg.blinded,
        ecdh_privkey=ecdh_privkey,
        message_buffer=message_buffer,
    )
