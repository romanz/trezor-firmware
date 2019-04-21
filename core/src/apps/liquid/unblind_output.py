from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidAmount import LiquidAmount
from trezor.messages.LiquidUnblindedOutput import LiquidUnblindedOutput


async def unblind_output(ctx, msg, keychain):
    peer_pubkey = msg.blinded.ecdh_pubkey
    our_privkey = msg.ecdh_privkey  # TODO: derive via BIP-32
    ecdh_shared = secp256k1_zkp.ecdh(our_privkey, peer_pubkey)
    nonce = sha256(ecdh_shared).digest()

    asset_message_len = 64
    (value, value_blind, asset_message) = secp256k1_zkp.rangeproof_rewind(
        msg.blinded.conf_value, msg.blinded.conf_asset,
        nonce, msg.blinded.range_proof, msg.committed_script, asset_message_len)

    return LiquidUnblindedOutput(amount=LiquidAmount(
        value=value,
        value_blind=value_blind,
        asset=asset_message[:32],
        asset_blind=asset_message[32:]))
