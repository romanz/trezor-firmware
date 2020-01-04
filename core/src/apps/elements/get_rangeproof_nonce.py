from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.ElementsRangeProofNonce import ElementsRangeProofNonce


async def get_rangeproof_nonce(ctx, msg, keychain):
    """Generate shared nonce using ECDH with our SLIP-77 private key and peer's public key."""
    from ubinascii import hexlify as h

    our_privkey = keychain.derive_slip77_blinding_private_key(msg.script_pubkey)
    print("NONCE: priv=", h(our_privkey))
    peer_pubkey = msg.ecdh_pubkey
    print("NONCE: pub=", h(peer_pubkey))
    with secp256k1_zkp.Context() as context:
        compressed = True
        shared_pubkey = context.multiply(our_privkey, peer_pubkey, compressed)
        print("NONCE: shared=", h(shared_pubkey))
    nonce = sha256(shared_pubkey).digest()
    print("NONCE: ECDH=", h(nonce))
    nonce = sha256(nonce).digest()
    print("NONCE: nonce=", h(nonce))
    return ElementsRangeProofNonce(nonce=nonce)
