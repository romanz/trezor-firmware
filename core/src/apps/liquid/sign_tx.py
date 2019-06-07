# WIP - NOT SAFE!!!

from ubinascii import hexlify

from trezor import utils
from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidSignedTx import LiquidSignature, LiquidSignedTx

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


async def sign_tx(ctx, msg, keychain):
    """BIP-143 Liquid style :)"""
    context = secp256k1_zkp.Context()
    prevout_hash = utils.HashWriter(sha256())
    sequence_hash = utils.HashWriter(sha256())
    issuance_hash = utils.HashWriter(sha256())
    for i in msg.inputs:
        write_bytes(prevout_hash, i.prev_hash)
        write_uint32_le(prevout_hash, i.prev_index)
        write_uint32_le(sequence_hash, i.sequence)
        write_varbytes(issuance_hash, i.issuance)  # HACK
    prevout_hash = get_double_hash(prevout_hash)
    sequence_hash = get_double_hash(sequence_hash)
    issuance_hash = get_double_hash(issuance_hash)

    outputs_hash = utils.HashWriter(sha256())
    for o in msg.outputs:
        write_bytes(outputs_hash, o.asset)
        write_bytes(outputs_hash, o.value)
        write_bytes(outputs_hash, o.nonce)
        write_varbytes(outputs_hash, o.script_pubkey)
    outputs_hash = get_double_hash(outputs_hash)

    sigs = []
    for i in msg.inputs:
        w = utils.HashWriter(sha256())
        write_uint32_le(w, msg.version)
        write_bytes(w, prevout_hash)
        write_bytes(w, sequence_hash)
        write_bytes(w, issuance_hash)

        write_bytes(w, i.prev_hash)
        write_uint32_le(w, i.prev_index)
        write_varbytes(w, i.script_code)  # HACK
        write_bytes(w, i.value)
        write_uint32_le(w, i.sequence)

        write_bytes(w, outputs_hash)

        write_uint32_le(w, msg.lock_time)
        write_uint32_le(w, msg.hash_type)
        digest = get_double_hash(w)
        sigder = context.sign_der(i.sign_privkey, digest)
        pubkey = context.publickey(i.sign_privkey)
        signature = LiquidSignature(digest=digest, sigder=sigder, pubkey=pubkey)
        sigs.append(signature)

    return LiquidSignedTx(sigs=sigs)


def get_double_hash(h):
    return sha256(h.get_digest()).digest()
