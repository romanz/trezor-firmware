from trezor.crypto.curve import secp256k1_zkp

from . import blind


async def unblind_output(ctx, msg, keychain):
    context = secp256k1_zkp.Context()
    return blind.unblind_output(
        context=context, blinded=msg.blinded, ecdh_privkey=msg.ecdh_privkey
    )
