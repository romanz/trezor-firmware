from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256


def ecdh(our_privkey, peer_pubkey):
    with secp256k1_zkp.Context() as context:
        shared_secret = _compress(context.multiply(our_privkey, peer_pubkey))
    return sha256(sha256(shared_secret).digest()).digest()


def _compress(uncompressed_pubkey: bytes) -> bytes:
    assert len(uncompressed_pubkey) == 65, len(uncompressed_pubkey)
    is_odd = uncompressed_pubkey[-1] & 1
    prefix = b"\x03" if is_odd else b"\x02"
    return prefix + uncompressed_pubkey[1:33]
