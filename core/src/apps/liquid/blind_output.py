from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput


async def blind_output(ctx, msg, keychain):
    peer_pubkey = msg.ecdh_pubkey
    our_privkey = msg.ecdh_privkey  # TODO: derive via BIP-32
    ecdh_shared = secp256k1_zkp.ecdh(our_privkey, peer_pubkey)
    our_pubkey = secp256k1_zkp.publickey(our_privkey)
    nonce = sha256(ecdh_shared).digest()

    conf_asset = secp256k1_zkp.blind_generator(msg.amount.asset, msg.amount.asset_blind)
    # TODO: derive value_blind via HMAC with BIP-32 derived private key
    conf_value = secp256k1_zkp.pedersen_commit(msg.amount.value, msg.amount.value_blind, conf_asset)

    asset_message = msg.amount.asset + msg.amount.asset_blind
    range_proof = secp256k1_zkp.rangeproof_sign(
        msg.amount.value, conf_value, msg.amount.value_blind, nonce,
        asset_message, msg.committed_script, conf_asset)

    input_assets = b''.join(bytes(i.asset) for i in msg.inputs)
    input_assets_blinds = b''.join(bytes(i.asset_blind) for i in msg.inputs)

    surjection_proof = secp256k1_zkp.surjection_proof(
        msg.amount.asset, msg.amount.asset_blind,
        input_assets, input_assets_blinds, len(msg.inputs),
        msg.random_seed32)
    return LiquidBlindedOutput(conf_value=conf_value,
                               conf_asset=conf_asset,
                               ecdh_pubkey=our_pubkey,
                               range_proof=range_proof,
                               surjection_proof=surjection_proof)
