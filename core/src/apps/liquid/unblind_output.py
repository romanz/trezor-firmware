from trezor.crypto import hashlib, hmac
from trezor.crypto.curve import secp256k1_zkp

from . import blind

from apps.common import HARDENED


async def unblind_output(ctx, msg, keychain):
    context = secp256k1_zkp.Context()
    ecdh_privkey = msg.ecdh_privkey
    if not ecdh_privkey:
        ecdh_privkey = keychain.derive_blinding_private_key(
            script=msg.blinded.script_pubkey
        )

    return blind.unblind_output(
        context=context, blinded=msg.blinded, ecdh_privkey=ecdh_privkey
    )
