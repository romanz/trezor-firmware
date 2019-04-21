from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidAmount import LiquidAmount
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput


BLIND_SIZE = 32  # in bytes

def balance_blinds(inputs, outputs):
    amounts = inputs + outputs
    num_of_inputs = len(inputs)
    for a in amounts:
        if len(a.asset_blind) != BLIND_SIZE:
            raise ValueError('incorrect asset_blind length')
        if len(a.value_blind) != BLIND_SIZE:
            raise ValueError('incorrect value_blind length')

    values = tuple(a.value for a in amounts)
    assets = tuple(a.asset for a in amounts)
    value_blinds = b''.join(bytes(a.value_blind) for a in amounts)
    asset_blinds = b''.join(bytes(a.asset_blind) for a in amounts)

    value_blinds = bytearray(value_blinds)  # to be updated
    secp256k1_zkp.balance_blinds(values, value_blinds, asset_blinds, num_of_inputs)
    value_blinds = bytes(value_blinds)

    assert len(value_blinds) == BLIND_SIZE * len(amounts)
    assert len(asset_blinds) == BLIND_SIZE * len(amounts)

    balanced = [
        LiquidAmount(value=values[i],
                     value_blind=value_blinds[i*BLIND_SIZE : (i+1)*BLIND_SIZE],
                     asset=assets[i],
                     asset_blind=asset_blinds[i*BLIND_SIZE : (i+1)*BLIND_SIZE])
        for i in range(len(amounts))
    ]
    balanced_inputs = balanced[:num_of_inputs]
    balanced_outputs = balanced[num_of_inputs:]

    assert balanced_inputs == inputs  # inputs should not change
    assert len(balanced_outputs) == len(outputs)
    for output, balanced_output in zip(outputs, balanced_outputs):
        output.value_blind = balanced_output.value_blind
    assert balanced_outputs == outputs  # only value blinders may change


def blind_output(output, inputs):
    peer_pubkey = output.ecdh_pubkey
    our_privkey = output.ecdh_privkey  # TODO: derive via BIP-32
    ecdh_shared = secp256k1_zkp.ecdh(our_privkey, peer_pubkey)
    our_pubkey = secp256k1_zkp.publickey(our_privkey)
    nonce = sha256(ecdh_shared).digest()

    conf_asset = secp256k1_zkp.blind_generator(output.amount.asset, output.amount.asset_blind)
    # TODO: derive value_blind via HMAC with BIP-32 derived private key
    conf_value = secp256k1_zkp.pedersen_commit(output.amount.value, output.amount.value_blind, conf_asset)

    asset_message = output.amount.asset + output.amount.asset_blind
    range_proof = secp256k1_zkp.rangeproof_sign(
        output.amount.value, conf_value, output.amount.value_blind, nonce,
        asset_message, output.committed_script, conf_asset)

    input_assets = b''.join(bytes(i.asset) for i in inputs)
    input_assets_blinds = b''.join(bytes(i.asset_blind) for i in inputs)

    surjection_proof = secp256k1_zkp.surjection_proof(
        output.amount.asset, output.amount.asset_blind,
        input_assets, input_assets_blinds, len(inputs),
        output.random_seed32)
    return LiquidBlindedOutput(conf_value=conf_value,
                               conf_asset=conf_asset,
                               ecdh_pubkey=our_pubkey,
                               range_proof=range_proof,
                               surjection_proof=surjection_proof)


def unblind_output(blinded, ecdh_privkey, committed_script):
    peer_pubkey = blinded.ecdh_pubkey
    our_privkey = ecdh_privkey  # TODO: derive via BIP-32
    ecdh_shared = secp256k1_zkp.ecdh(our_privkey, peer_pubkey)
    nonce = sha256(ecdh_shared).digest()

    asset_message_len = 64
    (value, value_blind, asset_message) = secp256k1_zkp.rangeproof_rewind(
        blinded.conf_value, blinded.conf_asset,
        nonce, blinded.range_proof, committed_script, asset_message_len)

    return LiquidAmount(
        value=value,
        value_blind=value_blind,
        asset=asset_message[:32],
        asset_blind=asset_message[32:])
