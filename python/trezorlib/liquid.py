from . import messages
from .tools import expect


@expect(messages.Address, field="address")
def get_blinded_address(client, n, coin_name, script_type, show_display=False):
    return client.call(
        messages.LiquidGetBlindedAddress(
            address_n=n,
            coin_name=coin_name,
            script_type=script_type,
            show_display=show_display,
        )
    )
