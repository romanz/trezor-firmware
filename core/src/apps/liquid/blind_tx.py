import gc

from trezor.crypto.curve import secp256k1_zkp
from trezor.crypto.hashlib import sha256
from trezor.messages.LiquidBlindedOutput import LiquidBlindedOutput
from trezor.messages.MessageType import LiquidBlindTx, LiquidBlindTxRequest

from . import blind


async def blind_tx(ctx, msg, keychain):
    gc.collect()
    context = secp256k1_zkp.Context()
    proof_buffer = secp256k1_zkp.allocate_proof_buffer()
    blind.balance_blinds(
        context=context, inputs=msg.inputs, outputs=[out.amount for out in msg.outputs]
    )
    dummy_ack = LiquidBlindedOutput()
    req = await ctx.call(dummy_ack, LiquidBlindTxRequest)
    while req.output_index is not None:
        blinded_iter = blind.blind_output(
            context=context,
            output=msg.outputs[req.output_index],
            inputs=msg.inputs,
            proof_buffer=proof_buffer,
        )
        for blinded in blinded_iter:
            dummy = await ctx.call(blinded, LiquidBlindTxRequest)
            assert dummy.output_index == req.output_index
            del blinded  # MUST be discarded before next iteration

        sentinel = LiquidBlindedOutput()  # sentinel value
        req = await ctx.call(sentinel, LiquidBlindTxRequest)  # next output

    del proof_buffer
    del context
    return dummy_ack
