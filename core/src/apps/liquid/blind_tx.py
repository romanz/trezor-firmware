from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput
from trezor.messages.MessageType import LiquidBlindTxRequest

from . import blind


async def blind_tx(ctx, msg, keychain):
    context = secp256k1_zkp.Context()
    scratch_buffer = secp256k1_zkp.allocate_scratch_buffer()

    blind.balance_blinds(
        context=context, inputs=msg.inputs, outputs=[out.amount for out in msg.outputs]
    )

    dummy_ack = LiquidBlindedOutput()
    req = await ctx.call(dummy_ack, LiquidBlindTxRequest)

    while req.output_index is not None:
        blinded = blind.blind_output(
            context=context,
            output=msg.outputs[req.output_index],
            inputs=msg.inputs,
            scratch_buffer=scratch_buffer,
        )
        req = await ctx.call(blinded, LiquidBlindTxRequest)
        del blinded  # MUST be discarded before next call to blind_output()

    return dummy_ack
