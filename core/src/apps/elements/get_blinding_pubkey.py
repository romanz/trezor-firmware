from trezor.messages.ElementsBlindingPubKey import ElementsBlindingPubKey


async def get_blinding_pubkey(ctx, msg, keychain):
    pubkey = keychain.derive_slip77_blinding_public_key(msg.script_pubkey)
    return ElementsBlindingPubKey(pubkey=pubkey)
