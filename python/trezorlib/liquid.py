from . import messages
from .tools import expect


def blind_tx(client, inputs, outputs):
    ack = client.call(messages.LiquidBlindTx(inputs=inputs, outputs=outputs))
    blinded = []
    for i in range(len(outputs)):
        response = messages.LiquidBlindedOutput()
        while True:
            response_part = client.call(messages.LiquidBlindTxRequest(output_index=i))
            assert isinstance(response, messages.LiquidBlindedOutput)
            if response_part == messages.LiquidBlindedOutput():
                break
            # HACK: there must be a better way :)
            for k, v in response_part.__dict__.items():
                if response.__dict__.get(k) is not None:
                    continue
                if v is not None:
                    response.__dict__[k] = v

        blinded.append(response)
    ack = client.call(messages.LiquidBlindTxRequest())  # no more outputs
    return blinded


@expect(messages.LiquidAmount)
def unblind_output(client, unblind):
    return client.call(unblind)
