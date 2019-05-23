# WIP - NOT SAFE!!!

from trezor.crypto.curve import secp256k1_zkp, secp256k1
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidSignedTx import LiquidSignedTx

from trezor import utils

from apps.common.writers import (  # noqa: F401
    empty_bytearray,
    write_bytes,
    write_bytes_reversed,
    write_uint8,
    write_uint16_le,
    write_uint32_le,
    write_uint64_le,
)


def write_varint(w, n: int):
    assert n >= 0 and n <= 0xFFFFFFFF
    if n < 253:
        w.append(n & 0xFF)
    elif n < 0x10000:
        w.append(253)
        w.append(n & 0xFF)
        w.append((n >> 8) & 0xFF)
    else:
        w.append(254)
        w.append(n & 0xFF)
        w.append((n >> 8) & 0xFF)
        w.append((n >> 16) & 0xFF)
        w.append((n >> 24) & 0xFF)

def write_varbytes(w, b: bytes):
    write_varint(w, len(b))
    write_bytes(w, b)


from ubinascii import hexlify

async def sign_tx(ctx, msg, keychain):
    w = utils.HashWriter(sha256())
    write_uint32_le(w, msg.version)
    write_varint(w, len(msg.inputs))
    for i in msg.inputs:
        write_bytes(w, i.prev_hash)
        write_uint32_le(w, i.prev_index)
        write_varbytes(w, b'')  # empty script_sig
        write_uint32_le(w, i.sequence)

    write_varint(w, len(msg.outputs))
    for o in msg.outputs:
        write_bytes(w, o.asset)
        write_bytes(w, o.value)
        write_bytes(w, o.nonce)
        write_varbytes(w, o.script_pubkey)

    write_uint32_le(w, msg.lock_time)
    write_uint32_le(w, msg.hash_type)

    digest = sha256(w.get_digest()).digest()
    sigs = []
    for i in msg.inputs:
        print('priv:', hexlify(i.sign_privkey))
        print('hash:', hexlify(digest))
        sig1 = secp256k1.sign(i.sign_privkey, digest)
        sig2 = secp256k1_zkp.sign(i.sign_privkey, digest)
        assert sig1 == sig2
        pubkey = secp256k1_zkp.publickey(i.sign_privkey)
        assert secp256k1.verify(pubkey, sig1, digest)
        assert secp256k1_zkp.verify(pubkey, sig1, digest)
        sigs.append(sig1)

    return LiquidSignedTx(script_sig=sigs)
