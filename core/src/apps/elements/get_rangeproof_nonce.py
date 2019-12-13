from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.ElementsRangeProofNonce import ElementsRangeProofNonce


async def get_rangeproof_nonce(ctx, msg, keychain):
    our_privkey = keychain.derive_slip77_blinding_private_key(msg.script_pubkey)
    peer_pubkey = msg.ecdh_pubkey
    with secp256k1_zkp.Context() as context:
        compressed = True
        shared_pubkey = context.multiply(our_privkey, peer_pubkey, compressed)
    nonce = sha256(sha256(shared_pubkey).digest()).digest()
    return ElementsRangeProofNonce(nonce=nonce)
