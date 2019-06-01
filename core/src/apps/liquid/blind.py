from trezor import log
from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidAmount import LiquidAmount
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput

BLIND_SIZE = 32  # in bytes


def balance_blinds(context, inputs, outputs):
    amounts = inputs + outputs
    num_of_inputs = len(inputs)
    for a in amounts:
        if len(a.asset_blind) != BLIND_SIZE:
            raise ValueError("incorrect asset_blind length")
        if len(a.value_blind) != BLIND_SIZE:
            raise ValueError("incorrect value_blind length")

    values = tuple(a.value for a in amounts)
    assets = tuple(a.asset for a in amounts)
    value_blinds = b"".join(bytes(a.value_blind) for a in amounts)
    asset_blinds = b"".join(bytes(a.asset_blind) for a in amounts)

    value_blinds = bytearray(value_blinds)  # to be updated
    context.balance_blinds(values, value_blinds, asset_blinds, num_of_inputs)
    value_blinds = bytes(value_blinds)

    assert len(value_blinds) == BLIND_SIZE * len(amounts)
    assert len(asset_blinds) == BLIND_SIZE * len(amounts)

    balanced = [
        LiquidAmount(
            value=values[i],
            value_blind=value_blinds[i * BLIND_SIZE : (i + 1) * BLIND_SIZE],
            asset=assets[i],
            asset_blind=asset_blinds[i * BLIND_SIZE : (i + 1) * BLIND_SIZE],
        )
        for i in range(len(amounts))
    ]
    balanced_inputs = balanced[:num_of_inputs]
    balanced_outputs = balanced[num_of_inputs:]

    assert balanced_inputs == inputs  # inputs should not change
    assert len(balanced_outputs) == len(outputs)
    for output, balanced_output in zip(outputs, balanced_outputs):
        output.value_blind = balanced_output.value_blind
    assert balanced_outputs == outputs  # only value blinders may change


def ecdh(context, our_privkey, peer_pubkey):
    compressed = True
    shared_pubkey = context.multiply(our_privkey, peer_pubkey, compressed)
    return sha256(sha256(shared_pubkey).digest()).digest()


def blind_output(context, output, inputs, proof_buffer):
    peer_pubkey = output.ecdh_pubkey
    our_privkey = output.ecdh_privkey  # TODO: derive via BIP-32
    our_pubkey = context.publickey(our_privkey)
    nonce = ecdh(context, our_privkey, peer_pubkey)

    conf_asset = context.blind_generator(output.amount.asset, output.amount.asset_blind)
    # TODO: derive value_blind via HMAC with BIP-32 derived private key
    conf_value = context.pedersen_commit(
        output.amount.value, output.amount.value_blind, conf_asset
    )
    yield LiquidBlindedOutput(
        conf_value=conf_value,
        conf_asset=conf_asset,
        ecdh_pubkey=our_pubkey,
        script_pubkey=output.script_pubkey,
    )
    del peer_pubkey, our_privkey, our_pubkey

    asset_message = output.amount.asset + output.amount.asset_blind
    range_proof_view = context.rangeproof_sign(
        secp256k1_zkp.RangeProofConfig(min_value=1, exponent=0, bits=36),
        output.amount.value,
        conf_value,
        output.amount.value_blind,
        nonce,
        asset_message,
        output.script_pubkey,
        conf_asset,
        proof_buffer,
    )
    del asset_message, nonce, conf_asset, conf_value
    yield LiquidBlindedOutput(range_proof=range_proof_view)

    input_assets = b"".join(bytes(i.asset) for i in inputs)
    input_assets_blinds = b"".join(bytes(i.asset_blind) for i in inputs)
    surjection_proof = context.surjection_proof(
        output.amount.asset,
        output.amount.asset_blind,
        input_assets,
        input_assets_blinds,
        len(inputs),
        output.random_seed32,
        proof_buffer,
    )
    del input_assets, input_assets_blinds
    yield LiquidBlindedOutput(surjection_proof=surjection_proof)


def unblind_output(context, blinded, ecdh_privkey, message_buffer):
    peer_pubkey = blinded.ecdh_pubkey
    our_privkey = ecdh_privkey  # TODO: derive via BIP-32
    nonce = ecdh(context, our_privkey, peer_pubkey)

    (value, value_blind) = context.rangeproof_rewind(
        blinded.conf_value,
        blinded.conf_asset,
        nonce,
        blinded.range_proof,
        blinded.script_pubkey,
        message_buffer,
    )

    return LiquidAmount(
        value=value,
        value_blind=value_blind,
        asset=bytes(message_buffer[0:32]),
        asset_blind=bytes(message_buffer[32:64]),
    )
