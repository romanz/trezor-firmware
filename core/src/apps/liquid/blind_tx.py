from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.MessageType import LiquidBlindTxRequest
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput

from . import blind


async def blind_tx(ctx, msg, keychain):

    blind.balance_blinds(inputs=msg.inputs,
                         outputs=[out.amount for out in msg.outputs])

    dummy_ack = LiquidBlindedOutput()
    req = await ctx.call(dummy_ack, LiquidBlindTxRequest)

    while req.output_index is not None:
        blinded = blind.blind_output(output=msg.outputs[req.output_index],
                                     inputs=msg.inputs)
        req = await ctx.call(blinded, LiquidBlindTxRequest)

    return dummy_ack
