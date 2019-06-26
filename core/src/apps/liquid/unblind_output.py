from trezor.crypto import hashlib, hmac
from trezor.crypto.curve import secp256k1_zkp

from . import blind

from apps.common import HARDENED, seed


async def unblind_output(ctx, msg, keychain):
    context = secp256k1_zkp.Context()
    ecdh_privkey = msg.ecdh_privkey
    if not ecdh_privkey:
        mbk = msg.master_blinding_key or keychain.master_blinding_key()
        ecdh_privkey = seed.derive_blinding_private_key(
            master_blinding_key=mbk, script=msg.blinded.script_pubkey
        )

    return blind.unblind_output(
        context=context, blinded=msg.blinded, ecdh_privkey=ecdh_privkey
    )
