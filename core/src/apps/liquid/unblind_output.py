from . import blind


async def unblind_output(ctx, msg, keychain):
    return blind.unblind_output(blinded=msg.blinded,
                                ecdh_privkey=msg.ecdh_privkey)
