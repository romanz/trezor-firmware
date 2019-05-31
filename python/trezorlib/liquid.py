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


@expect(messages.Address, field="address")
def get_blinded_address(client, n, coin_name, script_type):
    return client.call(
        messages.LiquidGetBlindedAddress(
            address_n=n, coin_name=coin_name, script_type=script_type
        )
    )


@expect(messages.LiquidSignedTx)
def sign_tx(client, request):
    assert isinstance(request, messages.LiquidSignTx)
    return client.call(request)
