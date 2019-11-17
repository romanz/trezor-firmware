import struct

import pytest

from trezorlib import btc, messages as proto
from trezorlib.ckd_public import deserialize
from trezorlib.tools import parse_path

MNEMONIC_ALLALLALL = "all all all all all all all all all all all all"


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_p2sh_explicit(client):
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
    with client:
        client.set_expected_responses(
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
            client,
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


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_segwit_explicit(client):
    inp1 = _explicit_lbtc(
        proto.TxInputType(
            address_n=parse_path("84'/1'/0'/0/0"),
            # ert1qkvwu9g3k2pdxewfqr7syz89r3gj557l3xp9k2v
            amount=9870000,
            prev_hash=bytes.fromhex(
                "1f9409ca03484a8c76b712374d4a5f4a73d2d290850c8f5d839dd1ee407e9476"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDWITNESS,
        )
    )
    out1 = _explicit_lbtc(
        proto.TxOutputType(
            address="2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr",  # 44'/1'/0'/0/0
            amount=9860000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
    )
    out2 = _explicit_lbtc(proto.TxOutputType(address="", amount=10000))  # fee
    with client:
        client.set_expected_responses(
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
            client,
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
76947e40eed19d835d8f0c8590d2d2734a5f4a4d3712b7768c4a4803ca09941f
00000000
00
ffffffff

02
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
0100000000009673a0
00
1976a914a579388225827d9f2fe9014add644487808c695d88ac
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
010000000000002710
00
00

34120000

00
00
02
 47 304402202e36cdf1cac38894e71b3b8dca5f8099c36a3cabbb3903a60fcd4f36de3f725f02203f60fcd01d8938385c571458e58e63eff84631ea9d9f46ed955de654b1d42cb001
 21 03adc58245cf28406af0ef5cc24b8afba7f1be6c72f279b642d85c48798685f862
00

00 00
00 00
""".strip().split()
        )


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig(client):
    coin_name = "Elements"
    nodes = [
        btc.get_public_node(client, parse_path("49'/1'/%d'" % index))
        for index in (1, 2, 3)
    ]
    multisig = proto.MultisigRedeemScriptType(
        nodes=[deserialize(n.xpub) for n in nodes],
        address_n=[1, 0],
        signatures=[b"", b"", b""],
        m=2,
    )

    inp1 = _explicit_lbtc(
        proto.TxInputType(
            address_n=parse_path("49'/1'/1'/1/0"),
            prev_hash=bytes.fromhex(
                "cdeb3c2fa32b057324a352565309ce7306bc8934816b8ad9980493052688a9d3"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=23600000,
        )
    )

    out1 = _explicit_lbtc(
        proto.TxOutputType(
            address_n=parse_path("49'/1'/7'/1/0"),
            amount=23590000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
    )
    out2 = _explicit_lbtc(
        proto.TxOutputType(address="", amount=(inp1.amount - out1.amount))  # fee
    )

    with client:
        for i in (1, 2, 3):
            addr = btc.get_address(
                client,
                coin_name=coin_name,
                n=parse_path("49'/1'/{}'/1/0".format(i)),
                script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                multisig=multisig,
            )
            assert addr == "XDwVf1X6qA2Ehqrxsc4LTaf3rr2bkE2tkh"

        client.set_expected_responses(
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
        signatures, _ = btc.sign_tx(
            client,
            coin_name,
            [inp1],
            [out1, out2],
            details=proto.SignTx(version=2, lock_time=7),
            prev_txes=None,
        )
        # store signature
        inp1.multisig.signatures[0] = signatures[0]
        # sign with third key
        inp1.address_n = parse_path("49'/1'/3'/1/0")
        client.set_expected_responses(
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
            client,
            coin_name,
            [inp1],
            [out1, out2],
            details=proto.SignTx(version=2, lock_time=7),
            prev_txes=None,
        )

    assert (
        serialized_tx.hex()
        == """
02000000
01
01
d3a9882605930498d98a6b813489bc0673ce09535652a32473052ba32f3cebcd
01000000
23220020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7
ffffffff

02
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
01000000000167f470
00
1976a91436cd5d96706462c435eb21069a913dc759dd72b088ac
01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2
010000000000002710
00
00

07000000

00
00
04
  00
  47304402207e7e0292857ffdf9bcaec5bd9f415486918041b09cf84455a5474de1c5376e82022015678925ddeee054f5e7505eb762f066ee999bdf8b919b106f837feaec93a84e01
  473044022073cadd030f4eda9dadbc5ae90ba67f1e339de9cd0e1d0f1afd46f3be11e305e20220174b488806670ea7f0777c46165db30593684cd123350bb9d4db1b53576d1cbd01
  69522103d54ab3c8b81cb7f8f8088df4c62c105e8acaa2fb53b180f6bc6f922faecf3fdc21036aa47994f3f18f0976d6073ca79997003c3fa29c4f93907998fefc1151b4529b2102a092580f2828272517c402da9461425c5032860ab40180e041fbbb88ea2a520453ae
0000000000
""".replace(
            " ", ""
        ).replace(
            "\n", ""
        )
    )


def _explicit_lbtc(obj):
    value = bytes([0x01]) + struct.pack(">Q", obj.amount)  # explicit amount
    asset = bytes.fromhex(  # expicit L-BTC tag
        "01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2"
    )
    nonce = b"\x00"  # empty on non-confidential value
    obj.confidential_value = proto.TxConfidentialValue(
        value=value, asset=asset, nonce=nonce
    )
    return obj


# $ e1-cli sendtoaddress XDwVf1X6qA2Ehqrxsc4LTaf3rr2bkE2tkh 0.236 "" ""
# cdeb3c2fa32b057324a352565309ce7306bc8934816b8ad9980493052688a9d3

# $ e1-cli getrawtransaction cdeb3c2fa32b057324a352565309ce7306bc8934816b8ad9980493052688a9d3 1
# {
#   "txid": "cdeb3c2fa32b057324a352565309ce7306bc8934816b8ad9980493052688a9d3",
#   "hash": "4594667f9eabc960113d339eaf1b783b019aa73ed60b162b42fd34d887602e07",
#   "wtxid": "4594667f9eabc960113d339eaf1b783b019aa73ed60b162b42fd34d887602e07",
#   "withash": "9ae5a1a0e3d8cef1c1a8c4392672af67d1ae5bdcb736e6a290dfd64dbb6ad14a",
#   "version": 2,
#   "size": 369,
#   "vsize": 282,
#   "weight": 1128,
#   "locktime": 106,
#   "vin": [
#     {
#       "txid": "28511dfc356422406d42398f10362aefacc59e12d6239192cd75f707daf86df3",
#       "vout": 1,
#       "scriptSig": {
#         "asm": "00140329ce46bcea46a9d3b765b45347f3ca9309c843",
#         "hex": "1600140329ce46bcea46a9d3b765b45347f3ca9309c843"
#       },
#       "is_pegin": false,
#       "sequence": 4294967293,
#       "txinwitness": [
#         "30440220181e8cdaaab1e837da3e27ae5599b8b174f65aa61b247cc105af3f2f624104df02205a053a364d2c164d740e89dba427ab02cbc9e86af828adebc9e9247c838f01e401",
#         "0381f3e1370b68fc50edb109faed46c44aee3542fa12e37621c14caa72772c515c"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value": 20999999.15183080,
#       "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
#       "commitmentnonce": "",
#       "commitmentnonce_fully_valid": false,
#       "n": 0,
#       "scriptPubKey": {
#         "asm": "OP_HASH160 146da92e8022aa0faee10287a805afdeaa435eee OP_EQUAL",
#         "hex": "a914146da92e8022aa0faee10287a805afdeaa435eee87",
#         "reqSigs": 1,
#         "type": "scripthash",
#         "addresses": [
#           "XDDFjMNRn8J5MSAizg6ojHt7v1xWV3ukcJ"
#         ]
#       }
#     },
#     {
#       "value": 0.23600000,
#       "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
#       "commitmentnonce": "",
#       "commitmentnonce_fully_valid": false,
#       "n": 1,
#       "scriptPubKey": {
#         "asm": "OP_HASH160 1c6ac16064f481c6557a6d5af6b380e99af3e250 OP_EQUAL",
#         "hex": "a9141c6ac16064f481c6557a6d5af6b380e99af3e25087",
#         "reqSigs": 1,
#         "type": "scripthash",
#         "addresses": [
#           "XDwVf1X6qA2Ehqrxsc4LTaf3rr2bkE2tkh"
#         ]
#       }
#     },
#     {
#       "value": 0.00005640,
#       "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
#       "commitmentnonce": "",
#       "commitmentnonce_fully_valid": false,
#       "n": 2,
#       "scriptPubKey": {
#         "asm": "",
#         "hex": "",
#         "type": "fee"
#       }
#     }
#   ],
#   "hex": "020000000101f36df8da07f775cd929123d6129ec5acef2a36108f39426d40226435fc1d512801000000171600140329ce46bcea46a9d3b765b45347f3ca9309c843fdffffff0301230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000775f054f90be80017a914146da92e8022aa0faee10287a805afdeaa435eee8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000001681b800017a9141c6ac16064f481c6557a6d5af6b380e99af3e2508701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000160800006a0000000000024730440220181e8cdaaab1e837da3e27ae5599b8b174f65aa61b247cc105af3f2f624104df02205a053a364d2c164d740e89dba427ab02cbc9e86af828adebc9e9247c838f01e401210381f3e1370b68fc50edb109faed46c44aee3542fa12e37621c14caa72772c515c00000000000000"
# }

# $ e1-cli sendrawtransaction 020000000101d3a9882605930498d98a6b813489bc0673ce09535652a32473052ba32f3cebcd0100000023220020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000167f470001976a91436cd5d96706462c435eb21069a913dc759dd72b088ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000027100000070000000000040047304402207e7e0292857ffdf9bcaec5bd9f415486918041b09cf84455a5474de1c5376e82022015678925ddeee054f5e7505eb762f066ee999bdf8b919b106f837feaec93a84e01473044022073cadd030f4eda9dadbc5ae90ba67f1e339de9cd0e1d0f1afd46f3be11e305e20220174b488806670ea7f0777c46165db30593684cd123350bb9d4db1b53576d1cbd0169522103d54ab3c8b81cb7f8f8088df4c62c105e8acaa2fb53b180f6bc6f922faecf3fdc21036aa47994f3f18f0976d6073ca79997003c3fa29c4f93907998fefc1151b4529b2102a092580f2828272517c402da9461425c5032860ab40180e041fbbb88ea2a520453ae0000000000
# aca24f3e96323dbdec552df90fd36dcc021ccfdd15b1159409f7d1835171b2d4

# {
#   "txid": "aca24f3e96323dbdec552df90fd36dcc021ccfdd15b1159409f7d1835171b2d4",
#   "hash": "3b8ebaa3d6e237f738baa0eee1e9366b48f552ac41c651f6dd23b4830632c164",
#   "wtxid": "3b8ebaa3d6e237f738baa0eee1e9366b48f552ac41c651f6dd23b4830632c164",
#   "withash": "5457a655554dbce80729aaafe51e903c2d98de21c639867136a55d59f301d091",
#   "version": 2,
#   "size": 459,
#   "vsize": 265,
#   "weight": 1059,
#   "locktime": 7,
#   "vin": [
#     {
#       "txid": "cdeb3c2fa32b057324a352565309ce7306bc8934816b8ad9980493052688a9d3",
#       "vout": 1,
#       "scriptSig": {
#         "asm": "0020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7",
#         "hex": "220020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7"
#       },
#       "is_pegin": false,
#       "sequence": 4294967295,
#       "txinwitness": [
#         "",
#         "304402207e7e0292857ffdf9bcaec5bd9f415486918041b09cf84455a5474de1c5376e82022015678925ddeee054f5e7505eb762f066ee999bdf8b919b106f837feaec93a84e01",
#         "3044022073cadd030f4eda9dadbc5ae90ba67f1e339de9cd0e1d0f1afd46f3be11e305e20220174b488806670ea7f0777c46165db30593684cd123350bb9d4db1b53576d1cbd01",
#         "522103d54ab3c8b81cb7f8f8088df4c62c105e8acaa2fb53b180f6bc6f922faecf3fdc21036aa47994f3f18f0976d6073ca79997003c3fa29c4f93907998fefc1151b4529b2102a092580f2828272517c402da9461425c5032860ab40180e041fbbb88ea2a520453ae"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value": 0.23590000,
#       "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
#       "commitmentnonce": "",
#       "commitmentnonce_fully_valid": false,
#       "n": 0,
#       "scriptPubKey": {
#         "asm": "OP_DUP OP_HASH160 36cd5d96706462c435eb21069a913dc759dd72b0 OP_EQUALVERIFY OP_CHECKSIG",
#         "hex": "76a91436cd5d96706462c435eb21069a913dc759dd72b088ac",
#         "reqSigs": 1,
#         "type": "pubkeyhash",
#         "addresses": [
#           "2deRWtvnVHYzezmnr5Q6E9gRsTXwRJjSLK4"
#         ]
#       }
#     },
#     {
#       "value": 0.00010000,
#       "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
#       "commitmentnonce": "",
#       "commitmentnonce_fully_valid": false,
#       "n": 1,
#       "scriptPubKey": {
#         "asm": "",
#         "hex": "",
#         "type": "fee"
#       }
#     }
#   ],
#   "hex": "020000000101d3a9882605930498d98a6b813489bc0673ce09535652a32473052ba32f3cebcd0100000023220020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000167f470001976a91436cd5d96706462c435eb21069a913dc759dd72b088ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000027100000070000000000040047304402207e7e0292857ffdf9bcaec5bd9f415486918041b09cf84455a5474de1c5376e82022015678925ddeee054f5e7505eb762f066ee999bdf8b919b106f837feaec93a84e01473044022073cadd030f4eda9dadbc5ae90ba67f1e339de9cd0e1d0f1afd46f3be11e305e20220174b488806670ea7f0777c46165db30593684cd123350bb9d4db1b53576d1cbd0169522103d54ab3c8b81cb7f8f8088df4c62c105e8acaa2fb53b180f6bc6f922faecf3fdc21036aa47994f3f18f0976d6073ca79997003c3fa29c4f93907998fefc1151b4529b2102a092580f2828272517c402da9461425c5032860ab40180e041fbbb88ea2a520453ae0000000000",
#   "blockhash": "3ff1c00c89271615ff111622eaa7935cae95a4e38ad5a58048f0aea7ef8f6c82",
#   "confirmations": 1,
#   "time": 1564342016,
#   "blocktime": 1564342016
# }


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig_csv_1(client):
    coin_name = "Elements"
    indices = [1, 2]
    nodes = [
        btc.get_public_node(client, parse_path("49'/1'/%d'" % index))
        for index in indices
    ]
    multisig = proto.MultisigRedeemScriptType(
        nodes=[deserialize(n.xpub) for n in nodes],
        address_n=[0, 1],  # non-hardened suffix for 49'/1'/1'/0/1
        signatures=[b"", b""],
        m=1,  # doesn't affect CSV-multisig script, results in same address
        csv=(6 * 24 * 7),
    )
    for index in indices:
        assert (
            btc.get_address(
                client,
                coin_name,
                parse_path("49'/1'/%d'/0/1" % index),
                show_display=False,
                script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                multisig=multisig,
            )
            == "XaEtEibtM5uecf62yVpXiFMVhCkuGdkKAG"
        )

    inp1 = _explicit_lbtc(proto.TxInputType(
        address_n=parse_path("49'/1'/1'/0/1"),
        # PREV TX 020000000101124b30c8c9f21a8952d5e577d39713ad87c4d94e07af0f5208311ec716bad66900000000171600149ff732eff0cc139b42c27c45279c2d1216a47a57fdffffff030aa1d95e1aed6fbb87cb8c52d7bbdb8b8b7fe0cde615c5c4f4c80d532f7af002cf08632d441b4d026c62c7708f41ef2ba17249982d49029ee33ece64382a53a7fa1603009c807c6f0139bb8a11d64f5ba19d5ae3720c2d9fa90e1e49aa8bbb694c4b5017a9149f05dc819845318ceb7fba0c6d7d8b8d273e36f98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000499602d20017a914fb1731356772ce6c36b525d7989092c21e385bab8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000006c0c0000ca0000000000024730440220464e51ad66aa11e52a257c2ebfd7666ee83f98683a0b6cc7ff87d56690bbbd5b022056301cd280a8d24a5466732f6bff753f1f08cb942c82307c07c6d47d83472f3d01210308fd4e19e632e376d525839a8479a03fef385d6426ccdeb56b79fa4799c257a00043010001d86aa3d69b25da908e49972ac7a2c597875b092714ec85cdc07064774f57d05788657ed034f65693b79b5cc4123a7a0aa16a4399425ee3dc06f385d03a18cd1efd0e106032000000000000000135a1eb0155b7495864aa5a1d2f39ed26dfe6fde5c3ac4714ee0d7b725b575531de83510dc56605f024251035cdb18e0e302874e6ea55f5848cd161c8af818dcb192bc4794be23e4e178881d66c6a0c8378834b5494ec85766539a9c752fee2bc90706cd9307293434347a08b1073c9d40268382fc46cf3d74c9f46b093916a19ad5709619aeae5379384392868c7cdfad44ac44ef5e836dd3a29bdb73711cb9edde3a1e16cfbc8d0039cb24bd7fed0afb3837f9f9e056d6c070c1b8cf6ba604f91294bdd238ede4823597dda4d3767cabb98a327c82118e29d2ae35e5ac6b2214f3d8c0a516d4de1ba85a36c2421d2aa2658f313299b6cff8e7e173b0b3b85b7077580409009f4f34d3b1ba9673a5c6cb6d7ecc338b2f50969bd0dc1097e274d42c9e995edd3963b7112192f5fe3ed30792e3f71caef9fbff05ea72cec67753f71b132f155ed670d560b47ebcab8210b37adf76e153324ed1e7e08bc641400e24ccbc998a38a9955cc203cee61827449e954203dc312e4421255807386538baec675f400f427d23b70770746eab6a05560fd99ce0a9bcf227b4c1611a391424b8216a42c4898fb8fbbcb1eed2966b64ec9f45d7b97c79a413069eacbff2754c15d256768db48f36ac4e5b77fb89716e02cea2a87dc7800546de23fd6639341d0488452d4f21890c25dbc63303a7746165e1d2a2c7b5ae3110ce3d62bc95a0caccf7d8e3e370aae957c85c9c0d76a673b043015f52cea1763277d791540f1f7edb022db4b68d33a719e7b0ec03de66cafbe01061a63d111d6ef6bfff4ee777ebd028e6a03e68ab8bb620358abc27372f66591022a9449e83f1bf14eaf7ab061552cc885dba74379dec3cd88bf884fd110c045aef4b5349c1469ed51cebc86e9c8d88aec62498f63fe1b1cbf7a304a46e5ee2c825f0bd673d9d34146fdc22dc86c807cdadc1d48b392f30ab4067f7de8271f2cf4395678664aac1819cdfbc247db321d4f379e6b02b4fb2bc3ce127cf4264dfd5f18ad096584b8e7ce20f0727ee31f184a6cfd8f56243aa671adca2959c35c069fa65889802c3d3119fb24009c2bea352e6611cc98d6d8b8c564c35f66a6960d429b92bfd8b72300b58ff7cebb04f088bd635545d90e890176d3a496114dadc985034c459712fab15f8f28fc86ce60b608012037289cdd140e4ba57b6e244ec4e98de6e0905db88aab0d2aa022caae33905f0cac135111025f6f82158c53c4efab61125ee135881e4b8fd604b32bf8cbcad94873cb1151caf478cc0d3ab3084e89dcf9204028e3d5ad855f214dece3ab2a9f60431fca817570e9e1214b0e1419e5fe5d6a4d383faf165ccb0afcf663f1c55b1997c01137d194f48eecf618054510384a93c95efd7d434743f130dcec7878f37108fee4ce93c4c558e07dfd82d988adf2f2d2673c10deed7758ee7b94117be0a0b16aa036c2383db89b7d0f4487c247317f66a85af131efeb3db74add38cd885b5ee4a9050e772f4ac65185ebf331c705da55d8741d5e813a03f21e948ef1dacb35534d8c91eae11f6d54f09dc0e370d44bb65f3694e7e7568cd446658fde6370287c6b11e0b6c594a08ef1d5f9afbca9146de97111452a248a7aa1c5ebf975fadf8bd7f6164a2e0845a28eec61b8f666408bf3d1096e20e688256fcbbeac8e628627f283a9782135c780033f0d90f806d36356bcbe582c3463ee63b7712ce1ee570f0d3811ab6eeb71d091afca6cc9bd6af8b83d4d8c620680327e8898da8acb87468cec04c5bd9673dcfd95b4b76d004881135511465d04978e47e7193755e2cb36ccb09d7ec7c5836f2d6331cbf9b49d7062721338c72c39622b433e9acbfce9695fc0a199265f0fbee391c814d7f8fec974cd8b8254a35b5419c1d2049da6b8d6072b387ec8504057b3d3c88310a9da662b810bc598a907d7e168d768362f11f751b107555f05c159084df05c10619b0ad4207246e343fab1cd9f67096db6afd1313dcdd4ec156af70d8009b9085b7c0da7f3ed08fc1adf5d7a135c836ce12ebd8827f11a89eb579f2568059aef5808905052cde463590a3e16cfba05ce0ee91d3161b45ed8f8c2811c7756a994b7233efdbe030d61bbf12950521b9a7bb212b03dffb29709eec75d72947be80cc910632353df3f1c57414e5129286784bd581370a83050d4bbb05f7d5250a715cb779e736c789bcdad2dbb5eb77097f311f1fc0be5d50bfaedc51267d11f20f6e5e2fc15b80e9943f647e78b00c5d05cddbf9352e6e3c19a59aed0fb69db862bc878db70acba8e2f7dcec41c54f20ca6439541825c37707790e3de7d5f53c5f882647d4fee36ea32f7759ac3b1b1aa1f9a9903d4fdc48ae145ba8ef1cb6a38e4cd5fbeffffb8ebf4bc59b52a3a91200c79eb756469c01990203b6f930e40d502590d7abc52b1f7ec7e1de76fdb351fe018209d2887f9c29acf736b9406454111bcc6fe707fc194f557380b5428e7a0db9eb5149ac90b00b0b640aee977deca1fda9b3b4328ba4ca972f8149baef3f7782af0d27e73041ffaba787a897ec54f672e641b43c748dc79aa3e97931010b7e520067b38093966446544e4477c426aacb09c0bcf98ff11c9a57e36f33cf5e645f84a1d2462fd311d8a068bd9acd8aca40a18b3339973d12d2dd3acb7cfd33a86b772f1cc1362495180c2d359915afd4fba14bed78f8d457b6fd8203efd7ac1a7793bc3d98cf92a22e12a26cfc3cf55ced2adde898b70560dfffdbd6fbea2db3cb4ac40c5ed2d80b1d28ec3ba8da70c4f2dc6d3f9c1fa71a862adbf7bac6a866be240d4fd44d4bb5dd46bcb4fde92579e7d7cf359983ba126ab2ea1d3f5877ccee41db1048285e37aade93146313f091d6e9db8bd84098f1b472c86311f73156b07f8ed78a0199e48a978b7477072f2a5c783145e17fc2a796a92e06b338a1e3f98bb321e05fbfe8dae9b3aadc591f4acbd8f10cfbf18981953ac1dad5f4101d9cff5ea95f612c01d7ec7db7896e3e343fcd3e0d8c9525e2e9cf5198aabe93944577acec12881c79115e9b592437d25fe001eaa137ae31a7df17962732c4d7f27581c6551d3cc5bc8c876cb3445403537cf42207b5ea704da43bfa213e877f1c7df919545da607fb59b1837fef8853aa54371314f000f195dcf940bd5c7ff8de549ee3646a739c45b9d421422fe64659cd2dc83393e99efa812fb5cfb4baa7b47557053cf367194875a834058a825abda0d5687621f935d3910ee3ccb14204c1693a2e1d2a21cd41e8c99008baacabeee2ff32b13c095c5b55c37460aa08f7da2050740edbac0e77d94b99f3b8e21067e08e1ec58c8c584f6023c53a8dd17b298a3b18cb5425835911944cd207d9d55a3d4863bca780586941ce7e86a5d192c43746b006a38b218a290ed963f4f1f80b9c05d35e573ebaec1e7f2a768d94b19dbcc979ad60a9bc7ccf0cb171aedf994301c77fa893d62d503ef2af035b26c54d1b6fdc4a4c464df5950a878390ff90bda3127703880bf59510af785316ff67a4fdfc4683555ff7cf0aa274947fb86b7541411682921a977db3e6129f355fd39f3c2740bac9e6d049590353e860cd4bef63006c53f029a58d2f342cb9e1027fcd951bbf2a0359034833c454ad4819f0c2ff3fa5677be6e154899d17556a85fd0519ec91b581108c96fd2fe7b8707bd31d271242df116281f08809aa82c53f052beda61b78be5655654cee0cade2dccf920ef95a9a5b83759f18d2b6336b7e24e307c475cc1195344a5468989b04c1774f2305ddb0f7d1d6739676c6b512dd762f7f273ec39089edc8398f100d8abc1f8a8cc36b2855c259e98afa3835067b21e91177ef3eb9a07fd284aa764b976d5faba27fca64fe7d3ef1a34b8168778deee43b504eca7c84f5bd03be560f2104ecefa593af1ae98c03f825183a2a8de917934e3f5c0034d83122b3aaa4fd77593eb6e288118851747e7af9794ca0754baf4355ff2368c2bea7412c626386a02f669f38460a2699a126c5d07213a6420f1960585e34375ca3b5fed9911b3efd74f45b1828a4462fa4d43c07068ee3681927be425aa8dd12713c140eca149ff309345ba6fee9e22d377cb45f58deaafd9f8d802841be91755e52a9228a5266f096f01b9285d4623a42e08663b788ad3f037d83ed5cdbec693b1d1a05b33bc72490503c1fce4fb59d37807f9855621e8be1b246eed7b4ac844ad6c6cb897b0a92aa4d01039ed6a9de5c3b218f4314fe7619cd08d695907088b7ad61f050d7082d0726e462055cc5bf116f10b315b624dcada12f715a3616d3ccb033c9e2534d07b18b8578f2ffc2ce6878c98051541ca6e396e73c762e0dfc5487472d92e75d935258ff55a695743dcc8087bd955a5606c8231fdc3ca7576ef4136502b1e98e6cc9fd0747a5fdd82b6121a6d3af27f6d487cc59006eef4dc4a17ec3b6520b6eb57d52b054d2d6572d7b9775d27370a1eeece8206694be8d41b5eb50d2c1f1d241edf4c91660eec12deca27a0d3ef3ee8e2165ed8619ed6e586b617ecf5d0ecbd3c062e6d28297d1eb3ae83ef49fb6e4ac95d37df8617038cc93933d0b26b778e2dc7d8e08dd324f18863811d285a002a0e7f575e0604329633239b1182dfa55b86976b6db53291772b2fdf5d83f833b73d678ee4aa7ddc22b11fdf0e81eb963cff9aab33be2c5da6af19a4da5af1691ef301f3ae843210c52dc13d8c482b4f9869aa70932905789da1010671b0e2dd73b336af1f90153d1e52695b6d6c0f471ae575b38cd1834fc981b47c3be1d4ecd09f254efb6fd52db7dd9949f13e07778139becb33a2693eaddcd04759ec87ccd0cff6d7780f0329087bf1ef526bb4cd71f0fdf0bc900a7e8e8fa5581e8e972ca93e3c6157780f182b46407ad83c0c4add76ecbf5ca1c6442b4fde09c3a94183e2ce67ad8c679dedd2e9f72d396e26679380b8c3c4d6025abdf0a4a7e459758a7a05b071be01d3e37ab51a05e92c8eb578d74615b5d754e93b6eb4542c9fb2f7d7ab36702e517e5f6addefded0768e80e642fc9818764897b6368f8ea1ac4deaadf5832b3190c2143946b7d93ecbaf03a4c143084151745af9a860b3a7a577a38619bac911a43b01d0cf92218e1bccef1a20c4f80b01b1b977851857f154bbe51da7946ad095b0637f0e16ba16508cad263d9c379fa659b440a65cd629dc03a07d0149bf979b3ff7423af27cb0817b39ccde19c2c7bc3b3dd88a10a66b3df65aa0441ffee03c2077ee013ccddf1f283c2d94941481ed771ae39102e9924466a15a40de4c27c9f11330f49a820580acaba1cc8e6ab87c41b63259a8362c6415b7227dbf4088e066600a084cf1f8a70329772ba5e095fce7f47ee6dda11187111bbc967979ccc5c6846e6777508c46f63af069462a2398380f3f2557702492ffce469de6f143783ad0a0b6058b6953622d8dd3f47cfb3f56b00b23f28fcdcd3bf240ed8a1f5e8b437cf27b8d9ee6eb5b9b33786d638dce62d1b39638f0608d3c19ad5dfd31c66d1c0c6464e6af4d0f261066cbb4f80c5c193d71318e2891d9f4a75da3614d3a2e2cae0e5414b00a2bff98997fb355c03d31cf34be05db83f1d376ba22620519ab518df290d09960319945b58db09611e923499a1d7537b74cdbc48149b208b7bdf4dd4b34eab19310dbac1f1c329e5e958e750fcf58eeeb0de1be23f1fdf467806a4c7f5f5298da2da743ee08309ca7a070e7daf11641c34dba54d353aada9408f5328ab0ec207a702b17cc786609005f9bb51400b0a39b7bb4224d13d3638a00000000
        prev_hash=bytes.fromhex(
            "a1f53093c4f4fa9ae4c3b06aedc4fdc8cd1dbe324631e0bd9c1b24384acb922f"
        ),
        prev_index=1,
        script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        multisig=multisig,
        amount=12_3456_7890,
        sequence=multisig.csv,  # MUST BE PRESENT!
    ))

    out1 = _explicit_lbtc(proto.TxOutputType(
        address="XDLMKBtydtPVx836Rbi1yvseKW11yFx4TY",
        amount=12_3456_0000,
        script_type=proto.OutputScriptType.PAYTOADDRESS,
    ))

    out2 = _explicit_lbtc(proto.TxOutputType(address="", amount=7890))  # fee

    with client:
        # sign with user key
        client.set_expected_responses(
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
            client,
            "Elements",
            [inp1],
            [out1, out2],
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    # TXID 785315fbb5e7effc2b8e34e6931ffa2c37af3f02e491e3d3a27ae0e8cf42cfea
    assert (
        serialized_tx.hex()
        == "0200000001012f92cb4a38241b9cbde0314632be1dcdc8fdc4ed6ab0c3e49afaf4c49330f5a101000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1f00300000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000004995e4000017a91415c53bbead6a347ea228ead57f54b49888a8f3c58701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000001ed2000000000000000002483045022100a05cc8fd4ec92471dd7d62ef3297243331d5119e45f17a68bcb007dafbf9d56c0220616a07c46809e62cad277d38265d4aef3be9a3b10368db49b374a473250780970150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac0000000000"
    )


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig_csv_2(client):
    coin_name = "Elements"
    indices = [1, 2]
    nodes = [
        btc.get_public_node(client, parse_path("49'/1'/%d'" % index))
        for index in indices
    ]
    multisig = proto.MultisigRedeemScriptType(
        nodes=[deserialize(n.xpub) for n in nodes],
        address_n=[0, 1],  # non-hardened suffix for 49'/1'/1'/0/1
        signatures=[b"", b""],
        m=2,  # doesn't affect CSV-multisig script, results in same address
        csv=(6 * 24 * 7),
    )
    for index in indices:
        assert (
            btc.get_address(
                client,
                coin_name,
                parse_path("49'/1'/%d'/0/1" % index),
                show_display=False,
                script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                multisig=multisig,
            )
            == "XaEtEibtM5uecf62yVpXiFMVhCkuGdkKAG"
        )

    inp1 = _explicit_lbtc(proto.TxInputType(
        address_n=parse_path("49'/1'/1'/0/1"),
        # PREV TX 0200000001012f92cb4a38241b9cbde0314632be1dcdc8fdc4ed6ab0c3e49afaf4c49330f5a10000000017160014997620931a525aa9c8ca32705151ecd4a9bbcde4fdffffff030b6df5904fc5a282621d61f90012ec94cc93d5fcc8454526b9cc5885e88f4ae20e090e74b189d60a372e1eb600abdaa11183ed88295590d3bb4c9fd2720c22f901fd03ba774bbd24ee0d7ed382f84e725a95b8954400705c86531e910fccd4562e18f417a914b1e44ae783d5b07f7d70b5793aa16877aa0470148701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000499602d20017a914fb1731356772ce6c36b525d7989092c21e385bab8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000006c0c00002505000000000247304402202f307aa37ec451f574c5399c5b1251f986071416041520c4ad20b17f15879abd02205e5d3d3d49249bce5b28fbd2add1188c9dae05503c7396f004d250ed487aef610121020875490e528602cfdbf1c95c19388ea717b1668922a45a559d83c97a01621c4b0043010001d0c0817c763b73b0f56c77578d71666bfe0181560568a8fef7f32d95c7d7355a345fbc4c18001a76499430948346b52a89d82d9bc2d8028d242787074ffb1846fd0e1060320000000000000001baddf6013cd68a047291cafa5caa1d378e8af8ee2a0e892e785df8409fda20cd407a3168beb9d46dcc6fcf9aa504adebe33dcc2fed5b89a8d0f110c79f21d9cda15569d6a82c01ddfb7f8809621b4ab8ba2d05352c6200d37723f8d75ff42bc6bee9d0c5e100b8c40561cdecd1b363b280bb27b5b2874a04acd384e23b2788931d94151b5dfcdc6fd7b86a9289f9ac1ab0db8b663d095b03115d250ab200d27bc0e5545dba1fa2b8493dd13cc0f3e2d9b7865fd284ea05890dad2a80e91e5fbbd09185066f1946c70ba077620f9a4707616419b65dcad5580153b25dcb924f97edca16fe928bae797ade9ae69f25a46a2ecf7341a34b45221ff1297915cdbe3b63e73f79e7483a50b04ad62516efc5ddc7a39ff4b3d65fc65a2e3fd3e027f46f2c199bfd6db873f2fb5f16fbc647cec11fdc897005d8343ca220810b87a8142549e7a35957bd68a11eb5f5d7243d48dfce1338a76b2a3d110c315137e216ebf407dfa6b62a1ba6e95662a3786e5495d4361a83ca5a3955c62cedbdce2e34452fc24390aae48674ff0f560e52ec119efddb70106940184852e5d072d7621387ae5f6a42aee69e727f8082d73d3bfc21cfadcc13083f0ba6b82b3ac8ca7e688cb1d5504f847744a076d2d92627f439c09fca760c3b2d093d0e646cf0d3a4a2a026d454c79b53a3705f5677da629d148321407a99805f7feb4a22e9aea59f02317b7b08ffeee1dc39ad3a48a70cc9172c2580813e3cde460015ced231f85343899052c4c4e4e5fff87d60981d37cafcd4ef29ecc2fcff6c917d9f09510e27a28b600d340468f37f4369a88e453ae78fa0800bae4938b3966ebdf1db32cf04d6d64793662f944dbe7d8696d038c0f63e14e4be80427b12d5567040a72cf032a5eb8fbf775d97d83a16d72ea77ac775432c6556467088cd3b00368902e6416f243f534e028b908d5c9a243964b4ad32581e1df30c86ac504dcd97c3bd451dcea16979c6c5df7e767c285480c3231cf89ec7118dcc6b2a3f85ec7dbd334fa88bab0e9b6358dfecf49e86ffefc86f7864435c1f06888ad8def56de38bfa71c4ac670a8ec6815255d940a2ccc5e1491aaa0697e830904221b79da4aed84f458e27e67b27be29f7982a32aace493c3d7387a1b6ec0043521cacfd0f7e197e0a9a44206b7765cdfe67122190a246f08e1c8ffa9dea59f7445a60d653b796218dad1b1a1eef609a235d6ae964cbc48516f6e32be92957e5a505adc829e6a871a5aeeeef58a07722dece6174e8524ac5611993d2cdd6ea2fe9c34b217eedcec1e5760c36799a4fda44d4fd6add39deab2306996036747fc4ea255f6a2f25f3bea60ebe25c147ad8d70ade6698914e432a4de71624d72900e82b4cfcccaacc2ebdd99a254742aa50aeaaa48ebded6aa070b8d91423dccc89b70ac62c085ee587a20d13f9ff6655b273837cd811ec712d76314ed819d2f69b9522da025d098aae5a8dc29562f1e9fa9f1170e6c517ae29f0cd17aa857332482453289f14ef92b0f96956a7068409657aa8708bba1e6b18bd5e60795df313e67cf9ff6eb98d297a3fe7a45f3abf2e6f5c1618929591fcbd76771e91174ae04eee15fc489027f95c257d5caecf8b3920129f2ddcfa18b7a7354bc7bf7a3172a8fe9b5dac2fe2eb0202cb4153b6433c6411d1c86e5fae04f18c86e6a28e12e1a61e6247d36e70c77bbaf5e85cf6c5fda605c4c0f8f3312dc3923d8c7561a6b7a28d082680121dc5c41b494d0b0187c82f0123f6f0e3470210e4231fb64414c9431e64667bc90e3fc8a4aa8d68372c55840d94942798b6c997a68697bdd39a41894e90a2a49c61c34d70dd4df17016700d5811aaac61a31c615676d1087ba7ea81699f84887878dbbf827a89e6c217019bea052541bd67e24592de141e1dbbbd9b30d0871daa9d5492bc9217dc161f5dabaf19864a3376f265c5ea0b5c6141475db72026697dbc736c09ff72c30078ff44a446a5a6b5b77df76ce9c44d30b939518e1a66153def488710eef511ce19afc2dd2bd5f5d8a33e6530fcb783b3ec5dafd0517611eba4dcdbb13f7ca5e18313a789c625bf99240a97c1beb575f9706ee105de97867fd9cf2cdd010f39e6c111b079313cfefddf734486dbb61a556d74f0c0b08ed9ae7022a4ca1d009e1f161307f634678683e75bc24ef10f862bbdf0f4c5a63ad2d760612d1e12a22157009fd9cec03c19f82f593e5177363b48ffee6f24ad66b1405f9c250d913b27be1c716a03ca1a3ebb4a4b8c988476e6cb1d6a891f8deee07f6c6b84f3e39972708ac0f46f9b61ba6abd3880e05da9c68b03f5ee8043200bb721677f893c1c343501efd3b997667afd2550cbda7ec0ac972714d49426eae7fc481a8ebff57bad8a13ce87ecd921da5c3a4c91fb25d8c4f4315a91e76e4c789a9d5ab9e0b28813cea139575bb5341dcb956499cda3bf4a785457345506e344b27d39df6358bca2d4dc12bb17451cd5f34ce3ff97cb9f6b13e99477a318707bfe8c0540d5a4bf0ab73ed7bfeba72ac7e5e6924a0e4dbb5a4edd2f1eb19e5b60e54eb32c7cd60bd5076d300e2a97e05da4d57c8f6212b3f9289a3579733191861a7c8456a0d851cd4ab20aa6072a48486c1c9c71ebf4c79800f15cb8fbddad9e066be0fb9017c93947c46631de3db9fd458b93b00a21224d52d3bd19782609c7d7df18c1768dc4e668c22754f8e4b94ed7607fa8fc18884c75f447025e4530b919682ddb98de23b7266787f3f2e78813e49b6f9013b2f4c88f9e270995fd515de9de819d90ca01c762eaa88b3105066a9f107701494ef56fd640676c2ff6677f6d8543ac61e6a3ba42964cbe5186de6a87eca71a066d74d5902fe1be662b535783794fca7ed447d356134ac68312da4d9d0287e62e990bc72a7ed7a72e042bd14fd4fe9fdad013e676788c218941ae0924c0ff2e21417225de6ac46fcd72afb1036e5c4a77e3871e0d4730842f2cdd49eead3d851ec8683ccdda12d57627aea835e470c04f804a33edfdd161a8fd89b1f85f720d561d19aefa841015413aed9785dca38c1166047b09ec64952091f0f34f872b555e2d94fbd877160803766b45d8a75e8c94cf486b37fa6f187d6b9d7b2b0b13dac4c2302263bcbb654b43f4091ad0e686153d81daee1cb64ac78fdeef398afab52a753cc36d311a58e9ce8900a387f44950ea2f8b36a4cb1884603e01b5acd205b052128e422370eb0eeef5402f6b1a4da1bdd1dfcbb24ff3be983f7433415f7c1371aa364922fa5c1908dd36f69aa8540f938c9ce2f9fef5e009982f3fc44a821f0a32741c083c89676c1966e003e0a0197777ac94fba0a23944328c4f7dd6f6b41ad0da32670603dcb85c3a2d2fed781b280d0b981f499944b68fd930760db722dc8ae159a16aa8d5033488f3180f86e8cd04852b197f878c3e71be8c769bc7320e0f001e389a431b24f17062c8bc1e6241ca06f6e3b4c027d414f91bd91288d7d5956e9a484612c77f61f0d850b108edf52491dcffc38801fdb46a532dd88459d8f9471dfbf09a80e61bd07ea3ec289b55c957cfacc792285db042c77dcf2f4245544862515c5de63ae9f08bdb31501f24eabd803c8e0a2ff8cdc88074b8dd868f2a6c503e33c068b9317aa868b66c82472f1c20a09b7dc07974c3b3b7cfcb9b8f0ea53f5635e2884aca90d58bdb1a582dc5899db9c77288d67d96412ef67ac90f01d8780ab2029264ed0a7344d611a7771cafe3293fccce2a4849a5cd11b2fbd2b132b56095fcf04e6ba7c4d909a04e9c012ef2e541823c2e3752a0f5963ba9fd84a8908bd10dea26b99926e0614468ed90774136d927d04d0b4e123fb587fd61f8630b636fd9fa66066fd0f0d4fe1161b9ce7cb3730b535bf953518fefd83e34ddf4374802e357858a303f13b723504c571171d183da0a746f8ceb53840cff1aa6ecadfe4706780be31c81bb7e633f05fc524e928ce40ea13d52aac705f9485e46e7910b9b92321bed477fc8f8a7d0881a7f7e0bf2aa85974e30f0cf1e4b4b8f67e0be2e19d4769102b24d9debd188a26f882ecdb70abf88569a03505461a156c858f817086ca99d10989feae85e007fa18e7a3adbe5d81a742f9bc29661c49c768fe78f68d8ddb4cd1edae33c5502621b1030f1eccaf9ec4925652cff3886c4b036f63932728199b84c34296afdd8793a6f138f408088d2e0cb38ffe69e5e089c22c1d401b14f40bb29d73bb94cd25b8ee37422284b708f41b443876cea94dc2f51f3206bf5813241040f819a0882c6b7a1ad2ca1bac48b77cb501da4b3399745246cd910fe5903813a2510e3a4150465c6cd3415c66d726a6d9fc540a59702c23084f3f3c4792bdc1059c99f134a8a265e05a261e0657e724c178f393057790604c2d875cc577a71839997128a676c678a31c99ab58218aebad71653c467f33a3292304593676e7ca6e328688da97c770a4f1e74284cbc70adfee955904da9158a7ee0fcffd1b41ec1385946164b4f97f8d97cdfbef58c465cedf5890c52c3777d843658f9c43863e6df26f1370d52f5c4bff7e55d43a1e725e008911c0f1722f6f3070f4d7fc0b29bbf1a66822eb88d6baa607a85bd5a0a1b6cea893291d1dfdf8d99ab9e1963ecd29a9f1bc30d48df708b78d5010518cfbef53e4905838d5e7fbf05d2e4ea25977580f70e51fc77ae1a6d1b44fbe7d5e39b68e2470079f82fea1b66be046bbd62dc74cc97246bdef8e6a4ad4ea56b11212bc717de92b69e8fe48fdfe2af3f07ca70618a1dc623b6ad7ca9dc52ea4757daee46989b0f3c1b9da9b0e8b411741459bda1f88634a4d15ab71b1ebc697fdc2b2259380aa7ec4526153152c8aa2f3ed9850b2a6ae8fb49675e658e908060382649383240a2810486617992e8e90b321bf604efdba6fa787225938e2067f2c0877d309cc88e4f391fd025e7da217c94fd2c30527401dd423779ea7716ce7e6e0cb3a5829d0b43288d996274fdb38183ccd3439cb3412cd16b360a18ad07da349962584f3cd0337ed09718523b94efe4f999e5c078ba4b91047768db7d853f853e4ed7a096ffa10c8a8b35f8a6d35f7d60bb124e12993b3bdd981a3f1f70bfd5b8417927dae321b360d5ca6ca72faf96be7a937fe8c44fe98b99a5a23e5f31e2f44c5d67bd37d8727987c5c5c6b9044ab6adf4ba81e65038ad5142e485e44c6a97fd029e79cde7e468e51b2a26dda14c2ee8d1bdff39f37554005a69767f739e505dcc709fa386e00b9fd0c0846bbfc754de1dbc751b2af253c92067414a921a39fc183edb9c50667506c15c372cee6dc18913bfe479a5e97640926883fe0100865a8088b8455a8584ab9c82f0d29570f3b59f8aa8a276d1ca7b9eaea7d09593890bf39079d04a5bec1713293adbe58050e234b6658b30df670ba5c134939b0309f0ed5269ccae72abc69055aa7aa9b30dc15140ce945460320da7adc4bdf0bef9b2e7b289f2fe704bc3eef379f4a06c5e3d99a8e9374c6102f50f3859c08f69828db58a186e0eae26751e1dfb3e0e481b8569f033dbf7db77be232db18c68b1304be934b4541fb4c330d399fb4057cb33974b3ba8df471635a7a40c0b58fcc51cbc65b404080e0312a4538ae029bfa8908e5f6ee07c2d6bc1b0ec89cf0d7d5a37439199b42b1489c8110de05e50bcccee91e6851667e1ad8714582d4a6e7665ff74fb1246c8f6229a26a7473aa2867b37bb9ed5d0c32aae0453caaa79f0ec9b73f544b363ce6cc2267baaaab7b3448ed5bf29fca4c309af03c415eadcc32f81100000000
        prev_hash=bytes.fromhex(
            "36e37514789e8da753df9ef99979b40d52e7b7ffd451498bd712453372a40e0d"
        ),
        prev_index=1,
        script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        multisig=multisig,
        amount=12_3456_7890,
        sequence=None,  # MUST BE UNSET!
    ))

    out1 = _explicit_lbtc(proto.TxOutputType(
        address="XDLMKBtydtPVx836Rbi1yvseKW11yFx4TY",
        amount=12_3456_0000,
        script_type=proto.OutputScriptType.PAYTOADDRESS,
    ))

    out2 = _explicit_lbtc(proto.TxOutputType(address="", amount=7890))  # fee

    with client:
        # sign with user key
        client.set_expected_responses(
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
        signatures, _ = btc.sign_tx(
            client,
            "Elements",
            [inp1],
            [out1, out2],
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

        # store signature
        inp1.multisig.signatures[0] = signatures[0]
        # sign with second key
        inp1.address_n = parse_path("49'/1'/2'/0/1")

        client.set_expected_responses(
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
            client,
            "Elements",
            [inp1],
            [out1, out2],
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    # TXID 60a50d9161a5df8e978c86ece8b23d76ab339d07235a37b5ed26094e55d3c762
    assert (
        serialized_tx.hex()
        == "0200000001010d0ea472334512d78b4951d4ffb7e7520db47999f99edf53a78d9e781475e33601000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000004995e4000017a91415c53bbead6a347ea228ead57f54b49888a8f3c58701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000001ed2000000000000000003473044022078852a3c2cb543138e56577bfe4a26f23b08331d0b587101509f50ccb73b03f80220461d196b401e24881c711188a4de7c33ab0f7091c4339f8f5b6dd344451fe5460147304402204f9f4ebcdee6697c5278ee7a142779ce9156168c2a950531fd6d7d6451b5a7d5022013012ab3606d81bfd12beada29721fec65775610c73f8a85396e4c7325df21c10150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac0000000000"
    )

