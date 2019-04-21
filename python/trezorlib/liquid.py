from . import messages
from .tools import expect


@expect(messages.LiquidBlindedOutput)
def blind_output(client, **kw):
    msg = messages.LiquidBlindOutput(**kw)
    return client.call(msg)


@expect(messages.LiquidUnblindedOutput)
def unblind_output(client, **kw):
    msg = messages.LiquidUnblindOutput(**kw)
    return client.call(msg)
