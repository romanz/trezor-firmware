from trezor.crypto import hashlib, hmac
from trezor.crypto.curve import secp256k1_zkp

from apps.common import HARDENED

from . import blind

def derive_private_blinding_key(keychain, script: bytes):
    # TODO: I guess it should be defined in a separate SLIP...
    derivation_key = keychain.derive([HARDENED | 77]).private_key()
    return hmac.new(
        key=derivation_key, msg=script, digestmod=hashlib.sha256
    ).digest()


async def unblind_output(ctx, msg, keychain):
    context = secp256k1_zkp.Context()
    ecdh_privkey = msg.ecdh_privkey
    if not ecdh_privkey:
        ecdh_privkey = derive_private_blinding_key(keychain, msg.blinded.script_pubkey)

    return blind.unblind_output(
        context=context, blinded=msg.blinded, ecdh_privkey=ecdh_privkey
    )
