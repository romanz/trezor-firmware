from trezor.messages.ElementsRangeProofNonce import ElementsRangeProofNonce

from apps.elements.helpers import ecdh


async def get_rangeproof_nonce(ctx, msg, keychain):
    """Generate shared nonce using ECDH with our SLIP-77 private key and peer's public key."""
    our_privkey = keychain.derive_slip77_blinding_private_key(msg.script_pubkey)
    peer_pubkey = msg.ecdh_pubkey
    nonce = ecdh(our_privkey, peer_pubkey)
    return ElementsRangeProofNonce(nonce=nonce)
