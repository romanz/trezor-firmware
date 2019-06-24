import struct

from trezorlib import btc, messages as proto
from trezorlib.tools import parse_path

from .common import TrezorTest


class TestMsgSigntxElements(TrezorTest):
    def test_send_p2sh_explicit(self):
        self.setup_mnemonic_allallall()
        inp1 = _explicit_lbtc(
            proto.TxInputType(
                address_n=parse_path("49'/1'/0'/0/0"),
                # XNW67ZQA9K3AuXPBWvJH4zN2y5QBDTwy2Z
                amount=10000000,
                prev_hash=bytes.fromhex(
                    "8fd1363b341478b4c04000e4f8b502ba1ab98db667c712c380763e6e9caacc95"
                ),
                prev_index=0,
                script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            )
        )
        out1 = _explicit_lbtc(
            proto.TxOutputType(
                address="2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr",  # 44'/1'/0'/0/0
                amount=9990000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        )
        out2 = _explicit_lbtc(proto.TxOutputType(address="", amount=10000))  # fee
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client,
                "Elements",
                [inp1],
                [out1, out2],
                details=proto.SignTx(version=2, lock_time=0x1234),
                prev_txes=None,
            )

        assert serialized_tx.hex() == "".join(
            """
02000000
01

01
95ccaa9c6e3e7680c312c767b68db91aba02b5f8e40040c0b47814343b36d18f
00000000
17 1600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5c
ffffffff

02
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
010000000000986f70
00
19 76a914a579388225827d9f2fe9014add644487808c695d88ac
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
010000000000002710
00
00

34120000

00
00
02
  47 304402203349ef6cad85ea7f4d1c9693678f551703d8a916f6aa5ac14a0f3d53eca1e10502204277c40b204bdd4bdd36b634f62a266a4730eaee83f2eda81c6f30186421604201
  21 033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf
00

00 00
00 00
""".strip().split()
        )


def _explicit_lbtc(txo: proto.TxOutputType) -> proto.TxOutputType:
    value = b"\x01" + struct.pack(">Q", txo.amount)
    assert len(value) == 9
    asset = bytes.fromhex(
        "01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2"
    )
    nonce = b"\x00"
    txo.confidential = proto.TxConfidentialAsset(value=value, asset=asset, nonce=nonce)
    return txo
