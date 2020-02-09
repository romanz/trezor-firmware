from storage.device import get_device_id
from trezor import io

# interface used for trezor wire protocol
iface_wire = io.WebUSB(iface_num=0, ep_in=0x81, ep_out=0x01)

# interface used for debug messages with trezor wire protocol
iface_debug = io.WebUSB(iface_num=1, ep_in=0x82, ep_out=0x02)

# interface used for cdc/vcp console emulation (debug messages)
iface_vcp = io.VCP(iface_num=2, data_iface_num=3, ep_in=0x83, ep_out=0x03, ep_cmd=0x84,)

bus = io.USB(
    vendor_id=0x1209,
    product_id=0x53C1,
    release_num=0x0200,
    manufacturer="SatoshiLabs",
    product="TREZOR",
    interface="TREZOR Interface",
    serial_number=get_device_id(),
)
bus.add(iface_wire)
bus.add(iface_debug)
bus.add(iface_vcp)
