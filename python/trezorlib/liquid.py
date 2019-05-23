from . import messages
from .tools import expect


def blind_tx(client, inputs, outputs):
    ack = client.call(messages.LiquidBlindTx(inputs=inputs, outputs=outputs))
    blinded = []
    for i in range(len(outputs)):
        response = client.call(messages.LiquidBlindTxRequest(output_index=i))
        assert isinstance(response, messages.LiquidBlindedOutput)
        blinded.append(response)
    ack = client.call(messages.LiquidBlindTxRequest())  # no more outputs
    return blinded


@expect(messages.LiquidAmount)
def unblind_output(client, unblind):
    return client.call(unblind)


@expect(messages.LiquidSignedTx)
def sign_tx(client, request):
    assert isinstance(request, messages.LiquidSignTx)
    return client.call(request)
