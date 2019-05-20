from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.MessageType import LiquidBlindTxRequest
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput

from . import blind


async def blind_tx(ctx, msg, keychain):
    blind.log_trace('blind_tx 1')
    blind.balance_blinds(inputs=msg.inputs,
                         outputs=[out.amount for out in msg.outputs])

    blind.log_trace('blind_tx 2')
    blind.log_trace('blind_tx 3')
    req = await ctx.call(LiquidBlindedOutput(), LiquidBlindTxRequest)
    blind.log_trace('blind_tx 4')

    while req.output_index is not None:
        blind.log_trace('blind_tx 5')
        blinded = blind.blind_output(output=msg.outputs[req.output_index],
                                     inputs=msg.inputs)
        blind.log_trace('blind_tx 6')
        req = await ctx.call(blinded, LiquidBlindTxRequest)
        blind.log_trace('blind_tx 7')
        del blinded

    return LiquidBlindedOutput()
