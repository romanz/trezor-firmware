import sys

import pytest

from bitcointx import ChainParams
from bitcointx.core import Uint256
from elementstx.core import (
    CAsset,
    CElementsTransaction,
    UnblindingSuccess,
    blinded_generator,
    generate_rangeproof,
    generate_surjectionproof,
    unblind_confidential_output,
)
from trezorlib import btc, elements, messages as proto
from trezorlib.ckd_public import deserialize
from trezorlib.tools import parse_path

MNEMONIC_ALLALLALL = "all all all all all all all all all all all all"
LBTC_ASSET = bytes.fromhex(
    "230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2"
)


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_p2sh_explicit_to_explicit(client):
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
def test_send_segwit_explicit_to_explicit(client):
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
def test_send_elements_multisig_explicit_to_explicit(client):
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
    obj.confidential = proto.TxConfidentialAsset(asset=LBTC_ASSET)
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
def test_send_p2sh_explicit_to_confidential_sign(client):
    txins = [
        proto.TxInputType(
            address_n=parse_path("49'/1'/0'/0/0"),
            # XNW67ZQA9K3AuXPBWvJH4zN2y5QBDTwy2Z
            amount=10000000,  # 0.1 LBTC
            prev_hash=bytes.fromhex(
                "d5c3191729b7dfce20741c993f29d519c794ea93deb4df6aae3322d67cb64f33"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        )
    ]

    txouts = [
        proto.TxOutputType(
            address="CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ",  # 44'/1'/0'/0/0
            amount=4995000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=b"\x11" * 32,
                asset_blind=b"\x22" * 32,
                nonce_privkey=b"\xAA" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address="CTEso55PoR7vk6WjeaVSRSofBvuLXzTxva7y9dWBxadi7wxBXNDRB1sUkuir5CP9WsFd5QqVisQNYBQQ",  # 44'/1'/0'/0/1
            amount=4995000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=bytes.fromhex(
                    "eeeeeeeeeeeeeeeeeeeeeeeeeec830f897ddf1d814c323cf89aee980d1ca0590"
                ),
                asset_blind=b"\x44" * 32,
                nonce_privkey=b"\xBB" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address="",
            amount=10000,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        ),  # fee
    ]

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
                proto.TxRequest(
                    request_type=proto.RequestType.TXOUTPUT,
                    details=proto.TxRequestDetailsType(request_index=2),
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
                    request_type=proto.RequestType.TXOUTPUT,
                    details=proto.TxRequestDetailsType(request_index=2),
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
            txins,
            txouts,
            details=proto.SignTx(version=2, lock_time=0),
            prev_txes=None,
        )

    print(serialized_tx.hex(), file=sys.stderr)
    assert (
        serialized_tx.hex()
        == "020000000101334fb67cd62233ae6adfb4de93ea94c719d5293f991c7420cedfb7291719c3d501000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209abe2f4f8fef2d7bf1d3cddb3373eefdec963d4f6da17629267ea523137008169026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb31976a914a579388225827d9f2fe9014add644487808c695d88ac0bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854086e96db6e173f41d6278a51a58d6f2b79484de159db8f0ea4009320f1522f33be0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b51976a9145b157a678a10021243307e4bb58f36375aa80e1088ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000002710000000000000000002473044022016e926e209d64ee6c0b7cf25308187ec58467f7fa409f04e8b034959580335cf022055e630b9cbfffc25521e5b8909294915c72282a1b349904e0022ee4d1f1133680121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf000020f09fe22bd404dbf1d52e03c5275dfd351ad8106101f92ba31fa7a085b53389f200209fb6b46acb0fb62ee1e65f80f8505f86b2ac8a8c4f39445e72fecbbbd63d4b530000"
    )

    tx = generate_proofs(client=client, tx=serialized_tx, txins=txins, txouts=txouts)
    assert (
        tx.serialize().hex()
        == "020000000101334fb67cd62233ae6adfb4de93ea94c719d5293f991c7420cedfb7291719c3d501000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209abe2f4f8fef2d7bf1d3cddb3373eefdec963d4f6da17629267ea523137008169026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb31976a914a579388225827d9f2fe9014add644487808c695d88ac0bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854086e96db6e173f41d6278a51a58d6f2b79484de159db8f0ea4009320f1522f33be0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b51976a9145b157a678a10021243307e4bb58f36375aa80e1088ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000002710000000000000000002473044022016e926e209d64ee6c0b7cf25308187ec58467f7fa409f04e8b034959580335cf022055e630b9cbfffc25521e5b8909294915c72282a1b349904e0022ee4d1f1133680121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00430100015ee947594fc776ed4088ab23fbf93e425a9f4d8602a16bd5f5286b983a8be6071401a743b106a1b859c0e8327a6c424adaf27c84d7af35342c186e8e43d74a3bfd0c0a601f00000000000000018c66734cd4d11c05e6cc89c5a6e82224dfbeab06a4259590682858aa4bf400d13b97e3f10a1696e7a6398573729619ee282e194be7eb9eaadfa49bb02f3ce5d571a066246e19989a6108678e15d7616613963293a6b30b81e0ce5b69eff2e16c3133531db166e29b226048607c7ff7ca9ae2499d4dc381592ca24bb449b5e67975659064efd2798ed9f6c2f23593c5fcc40692d99ca58971c2625caa67cafc9588307823ab6edd37bdfdb7130602decdfa8fd39fe6d6f8f5df829cf242c9940178dbf4a37df37f4374efe89195e9641b9344a06b8dd6028f57906f6db6a3a928fda81fd2728a352bdef62f79fc1f9b0b53bac6b672925c9dd750827032d3434de9679a63db65afaa4448bdc32e06eb59e662fa8e2c55e14e5a9dd0460e00fac1d5c908b76bc07034e72e837b65321628ea6aa831ac5679afe6f9656c60c471a7e14d25c3791c15fd5f0e2cca354dc34c1f79f228f2ba5f807cf03432803bad9c28f2a9b88537e02f822aa16991b77e3153d78e8bff5d8e224563c157a3c197067a3a93f352a1405039e63923fee925648b5e9782e9a7b6e501131f7d2115ceddf15845a4e3f0f8abc94fbb545a320bd75cec688385c5e19cc68523f413a75fe1ac3eff6c0c71dad43b00c7c2d25be82e2ca32f7364ba6453304b156a65e8a0b70a7cdfe28054e5359fbe89dd94b33b6cfac0f069780f3ff27df7c11efafe31d1055e0f9ecc8976aac5f3ecf1a2734a1fe04b7f1a7ffb4759afe49881a9e3c4a78bee42cb8de5b6b1a8abcdf3d96e3fea119eaf514a7f34e8b71299766fa840cb0c881acb366cb46455c729c84574a166d0197036d75c8c0c6a2861dee915e66dcf5ad8c8fda0972fdaa10a6e0a8a449d7729fb4ab6c5ea1c034f4dc25337a0d71d1b9fbd7aaffe574678f214dbf8ff89bee58c725d5bccdb6d46ba3a8f81e237724d71dd6c156e6cb0a20e18eba07f4aefea5a722be76cc53525216119dd900c9690db506a984d4d681cd338b9495fdd3b580bb79cbbab63d94ba1b644e8aec966014b16a0a05d3c619d626e9a2a33f2ffed4758261c99c1c2cf1c8abcb5c978c6b6a358d8e2fbf5e7fbef92b235e5936fbb95e48e79a29ac45910d981fd7babdc658775e0c040f212aa72ec8a00c6d3ca375276c5c863f03faed550eb6f36339e5aae3751376371f3783108e270ce531bb9820a70283235f5af9d0dbc435a9777463d5ebd6097eb266f07ecdeb3bddb816fa1bad5358e8ab03c80abc155151a941bcf8a0f010cbf501fbd04e59e9d77f13b0dd2c6c4cbfc45b5fbbed59d7ce8e0f8d70e8f673408c1afcdb2deae6c92acc0c882642fa1dc8f97ee4d510d040b696165100d5e0b26dae2d36eb0e2e9b44c7c2aafbbea7fb4d2e7eaff169799c922aec031bea4c209760189069592348bda967cfeaf5d65d0c4eb54d2cbe6d4efded797ee33b389b6b46d9cf524b02d3338d011e354eaa4b74532c9bab8ae29df094de6b8ba749393884e2a7e814a955c2bad1f84ad46d5459c21b2e60b3b484c38a79a3e4c138c5f9312824bd2d1cdc9752a015d5388baa8a64fba041434f4bc0532e7578661c666bb82fdd5df843d156b8984f9668bcc4e0baf6ca0c8db587d2e7b05e98fee818d939b7b398d9d77f7667b67ba33c6666f077f453653feca3bcf11e5d1645c1c7f66784cd6235d1e8f4eec49565d8d86b2eb56ef78d5c59499803a34ea497b257dd4dabe4d92e35fe7d299cdfb724c949e96f5a6c8c0236f2f69339ae6d88ab65c7af9f8cec2ce80230a72cb562643531165a6e8c5d5c4a452f6cfa69c712f3b1f2b74534654a05f2008c2ee74ef1040edb293a4a80977f515024e9aaaba8d7f620f4bdd42ef39b9c62d39f64cee63e4737b38c8f8b35e7406226fb1ad438826650eb9949358179dfd41b5fe3c21bd782a58f1ab5dfbe8370179e905089cf472cbdf7fbb9f84d975f0b8bbee007090cc675463ea2fe2a89ca9f23211230b39b98dac26b2726577825d08442caa93e9a99cebc001a13de294dcf70a3b2d1d927f451b5e5036791234a0c73b7241a3ec0baa2bb9540839cc9aa05de9840e51eed8d9019c3a1e84979164e1031fc44f6c3009670adf92c72bd84f4ecb95eb635b896428d6cc735f9393c1991db26135ee2f3569e46e83e16cfeed59a04183801fe13d66ad0c48e46c6fa2961dbc35a92331540b91bd112dc07a40cf3b927a5535ae184e7aee6d3990dbd52db218883567b8716f21b40e1d999d54fc01b8f56cb1701c9b17fa7e47d5dd68d89462a4efde44a502ffca18964613c762186b17f64170a2a1d06cae7ca151c0323097cdaeac291da16725e97aaf0f6437db3444fedf4223a2eaae7067729cf6bb5a9b75a2caeaff271e5348adc73f9ea77ac7ee850974097c2d0d30acb36ed0fd5f2963b103201eaa9c2614dace01dde7daadfeb6dbeeaba9c8695bf2ce2781d5ec1156e0869613d36fe85dd8a41f1fa6ddaae190562194cd8aa2ed455d2aaf257fadf8b363ab9209725f32d52fbaf7fa07031a030f181b1d1c67d1e1f55837afe61c482dc4c910f0a31cf7c3f10af8f054ba3c47226abe36f0c49acba6df2440b4a02ca27fe798d1b53693b21786160a95117ecbb65c89036ae0688adbb7175aea039bbb2535e04fe5ba9bbae2581b831c6aa5736d705c3a8f6ca28eda077f863d7c55a080ab7a7d408dfafd8dbde03efced55504b6ed65737be568f21584cf23fe56fcf3679ea7aeabfd77646d7714edaf2178b526902df2c3a68c6d96eace6e74822c6fead2211dd0809548938c5284876ca08ce892218026329a256a1c5c33591087acea63fddc041c8eee3d44d382b6a03d69e7336a3850225690960f8606701a7eab98b0930222c2127eac76dd940cecf21d6f570708ef25b223306b3194de9d04ff49e5d646bc7538a682ce45f8a39722a682b80708a8f851a712f119a523e943db80b734b1ff9c24ab4c2ea79b4e564346d7dcfa0fe8e1c2e1377cb3c79cabeff1e4440e69aa07a063e25bceba91413dae78d25eb1b8f90c81ce427b8854427469a3ebd406e613090bf932432b40be990d337b7357afd1060209b6c0cf70878b82fdbaebe2db96bb67623b85f26ed58f0752e3b0ead3a1d5f9d85a06f90bd40474a5c426867737c9a62736ac85904352043dff56fb0a5ab7643502e9eb9928a226e0e70b55ce0bb4c325e3daf1ec92f7b33a2e549d9cab364d2a6d3f7c0a43c5717c1932f3ab6c94f005638066ed963b3a862ef9cd937a5db08ff902ae55c2874a14a491c9273d5cebf509e7687140c1d73a28600344ea28f99f5ab1081a2f4b7e70b348f4aa879a71bdaaf162651bfe3b677dbe2308db11453bfa4d0de20d0953233545a7b6b4dce63be88eac22ebf1aba44009c6f69df1c937c68ca446097fc41784fd946d58d63598c798a0f0903b41358dbc3521dd9dfa409fbf3ae2af68169654e25a3f787bcef96180c5021cacb77b10cc457096f934ddab5719dc8c95451f3e48ebe6050be832cbee0e11a31e6db1d804d67fe749c2f89b14824ce94afa1008453c881978d2596b4753fdf5b8640cf6a0c2dedf5de3e0b4fdc18e0a565228624e25b3758ea8379bb11e4430100016b12126b9240c5ed07aad69fd5d667b56da9a6f24228b6084f0121ad0f405b8df168becdeb216d645eeadef86cf7c7cc7d2250c912e0607d0b0c8f7301ad4a43fd0c0a601f0000000000000001fb2fd5c340109907e6e40b8fa880e8070d7268022ac844e8a234fe02252daae61c5bc0d16cf974ee9851672dc2d48013d70b88d9f8b5a2573309ea7399fbf88de9dacad356e82942caea9485f4dc22f4fa7e2aa453236c889e726afc88949fef26dca9731e3e19c95e0f1c5b246aa9601bcc933220d2b4242fee9a555750816cbf43c6051b9fdd93374e02663fb8fe4893f83af83398743ffefa7208f67cd98d59f91c9b4709f09150585d52467d5dff30864dc17d00915903fb27005a5b3b6c55033aa8ec3ce026767abeaec9cef7d43d1293b4280bb6e44d3c626dc0a5140c62d2b1d33b267005dc58c26c28c5a6e0043ae5b03f156ab4e956412c92a7646c7f1c4134ebef1c0ca3a790f9b15bd4c82747acec139a3ca9d42292f4b2169e05d436779bc0e7a151feeb8ecfd58b3660ea92aedcdb0801b99ec6111493863df743692992e5253137027f0337ba0d06fdde91bed9e90020ad04c4e77f7c5b1ec97a1f3a8781a1068f79f3635b976076a76ceba80fe077df43ca11349d675f9176162dd88a0e58901a1c9e8ed42c87ad01b7b645856e53fae5dadd47a0eda4d09d07492ddc6dbf12cb4d91eae97f424460a2e9ef5fb11896665a19fe9d889fb1129d71f5cd3d2c8851a3f8173be9772b28e3a6f561795ee1e7580e7d55e5cbce15b120906ed85a23710f7bd17a8ec8df58f4e9c9dc1495c3bfc27203d86c6b94973d2256840face2c1b6b7e4fdf081d19ba97c4620a059ea295641c53da147d68dd48a0223894b660282f53a78caac10819e03eb346499d0c5b11912391d87da1af7d5c57c2ce772586bbc11656ea32b1f2168dae8e91b0d202a8b38f0442b9c3e97cbdfc1493915e08c216510a0b81b5ccffed9a8ca966b60fc08fa14baf9ea6db8270843d475ece05c29aa4789ffdae6ca97d5b544699ce4e071dce504f8f619d7a6edecccdb56ae8b98da82bd4bb24150fc8c7a5f86c42d8982e285879e1412813a9c7dbfc445566e66fc3380dbdc837594175e44db7b355ea447499bad991e2c042366fa3a84ef260382d9ffb18494b29c0574f5495a1339586b15c2f8d4117fcdc7e0c5e81927773b1f712e34f11555b01f398401619f46334245e1879e741f9fac327cac8adf1c3335d6881f25d9dea1972b1e691438185f14e5d6b271f708cd95d071c32ccf8d22fc02f49052b46b5dfab9581f30d2a4226990ee308655918d3e95043dc0a2e1894a9b048cb0d4ef6e4d1af82306f139a319b533b7f75a641c0516912b6ec33aaefdfe4e7e1ae9c44681251ebe6a4232248115d8f52b099e079d126396129890338ba8b9025db620d87ed64652aac40d2f19289e16063d1ad468e4056b22fa31541a9a24b748354658ff94b4d9919e1d7b7ca20a52066eb27e5577f553c7b6f423640d909e0b53d0e3094cca8173b0a070c44cb76a113e0778f5901005e748d448f2e67d5067d3a729cca475c64a4cf02333bdb47bd6e4b343895a29f0082347b114d9d0128150d976bbb8bac695d4f6129a7ffb332f7c9ec26187f4b14f273f4a71fc4bfb7edf61a1d059cf3855e092755eac429fb9789a93c7eb1cefa030ada3bcecb22d0a824a25cbadcf64a675a67fc3197d3770c67cddf0607a0fe796c412fa161a6057b37230668fd4839aa1881f28a0e6761980915f111e2485e64a3a4927c920a194197574a476fb92d559618b02a35f671ccdfcf517ea377a37daf97a39946bbb985e22207da1b9991dd269875e2e60704d5221cd089cc29decd21f4671f26ccd78048c52384242f90cf3cca6ff2e29ead099abe0f5036590831589b4b2ef45a1475884258019379547a00dc2370dbb254136a91384c66796f35034863fcd970e0f779a189d95d5fdc5bafe9b60f73bce531c81cf16b7f42a08192779619aa5686f6637023268d67054df86dffaba4089c8a5a28e0cc1825f92b35b4e8d8e3916bf15cd07122e39a8dc0f73646ed154f18136b8c2c58fb25ff934ea30347b64b49d624eecbd529a4a2e46a8a1768da22ec6cc9117777d9084079aadfb9584ab8ee105ac51c1739e0abbfcdc848969279b78ad56d47bf3cea2e7c91a03026540d40703400316914a69565a444d4bcaa1b88f76fd694907b7c2c7d38ec67488ee3ea9c47d29356fc26182af559e5d9fc194d6b1e808b201474e8e5f3dbc03760861da931df413c877d8dab9c5724f4528545d742689396b90df65819f46d5005c5eb44044090c1806d1f0d96d04887caa33b2fafa6a97f83ca934da1cf38b526f3d421bb2610433e988fbe30124b0fab47b42e8c484a495a978e93191658d2b00019285e6a6c2cbbf5b351db312971048fcc51f6fc3289f6a2b0a8cf993d4a55274dcbd07681f49302ac1bed7cec0da1dcafe73b6c9f11ed893545ce9c40805b56074a7a5696c58c09211a37602ed4dca664f614580e3bfd3f87d93bdaf0c797ff38d2ed035f0fdff211f6604a6431a4476bcf0898ac850a651ed61b5d80ffad707f7e65cd41f0580cdc9b73444019f2cbc12196427e54623843405f9cecca313e062721fcb10081257c324a925a54cf01194c7691cc391b2a3b351540c114705e6d58d4f9289582f388f058da763d29eced2c1c4f1b4dad2d0c115953e6d20fab1c00080ba2eea2b6c75b090ccb34750c3f953de1bdc008f6bbb6548571d0e34e02c6e745275820de2f4f5e7a05153389bb4ccefea30d94d3361aa3f5b69eb272890be84643662407fe590a26beaf265acde68c856bdae86878bafb3c0f9ff60afbff027dcd99be965c24e27487bdecb03577c4ee684aebb8a1178eb7afd5da4c00dff8a7dc233b384b867ba3b8017c1c65903df441807983b5767576c00d208a6dcbeefa1e0dcf45b1ff6c009d4074a1f28ea8203cbdc53ededbecc317f056efa3af01b560430345c5a5dc8e3f8e5bdba83c4d394923b1a5c82a4893107172137390b01ce1ce58c3dcd1e7fe9bb2fabb73250d57daae59c1e36e94f36d968fc5204c21351f5590430a575c92d1160d4c6818891983b9dbc0d01f376043dc28543b9c1ac950481bdafbe155c42e8f63ddce31c49b03cc655bb6bb31c039f5d5276f9f64c6508f3e387f2375bc864f31f10fe8284e97f449e60429cfd000a7404f6bc256bf3de65fed81aebc902e34cb9f6eda5e2209fc35475f04d39d885d95343f8bc73fab1220efba793ba9b6b09f4a912951e2c3853d8d3de266d34b39e3afe9859d1a4a0152e070df567738256e59e7b3478c3e929498c187612d75902d9fb40b539c004c12fe3dec663782eef818a1d1d34d8eb4de6e5bf4a6616d2fd036a947a6abee720dfdd1f2c1ed450ebd3e95b145e2f865a14e076b455ef5288dc38dffa14cc6fd5be58bd2b87a9fea886cfbe739fec109a419775151d38e0774b7d091aa2280cb0e07555321806a97e519f72f59f105d3a1fbe64427e763e2f3e0d9f59ffc7edbb1582b820d73d80931f125500dacaa23131eba98e7feccc7b88287c47896a18a6970aa5956a3dd6cb053c349392cc2b0343472e7dd332a55ececfcef5de4a3ec78eba9f8ec5fc08de031cf5bb385292c241a5b10814270a72ffa5cd9f258bdf000fbd1648107443774e6376ba85d60000"
    )


# $ e1-cli getrawtransaction 434c8afb198b30ee998899e84c9c58af92ff4a82dba9da16431a483e635668a6 1
# {
#   "txid": "434c8afb198b30ee998899e84c9c58af92ff4a82dba9da16431a483e635668a6",
#   "hash": "c453ce42ed0919675b9f11891321552f26c83d55b03d72d11d4bebd75bb5a074",
#   "wtxid": "c453ce42ed0919675b9f11891321552f26c83d55b03d72d11d4bebd75bb5a074",
#   "withash": "2df1a9752a711847bf33a872d97c91238f1ae6da76aff4a466347a40b3851f59",
#   "version": 2,
#   "size": 5767,
#   "vsize": 1719,
#   "weight": 6874,
#   "locktime": 0,
#   "vin": [
#     {
#       "txid": "d5c3191729b7dfce20741c993f29d519c794ea93deb4df6aae3322d67cb64f33",
#       "vout": 1,
#       "scriptSig": {
#         "asm": "00140099a7ecbd938ed1839f5f6bf6d50933c6db9d5c",
#         "hex": "1600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5c"
#       },
#       "is_pegin": false,
#       "sequence": 4294967295,
#       "txinwitness": [
#         "3044022016e926e209d64ee6c0b7cf25308187ec58467f7fa409f04e8b034959580335cf022055e630b9cbfffc25521e5b8909294915c72282a1b349904e0022ee4d1f11336801",
#         "033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "09abe2f4f8fef2d7bf1d3cddb3373eefdec963d4f6da17629267ea523137008169",
#       "assetcommitment": "0bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac652",
#       "commitmentnonce": "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3",
#       "commitmentnonce_fully_valid": true,
#       "n": 0,
#       "scriptPubKey": {
#         "asm": "OP_DUP OP_HASH160 a579388225827d9f2fe9014add644487808c695d OP_EQUALVERIFY OP_CHECKSIG",
#         "hex": "76a914a579388225827d9f2fe9014add644487808c695d88ac",
#         "reqSigs": 1,
#         "type": "pubkeyhash",
#         "addresses": [
#           "2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr"
#         ]
#       }
#     },
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "086e96db6e173f41d6278a51a58d6f2b79484de159db8f0ea4009320f1522f33be",
#       "assetcommitment": "0bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854",
#       "commitmentnonce": "0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5",
#       "commitmentnonce_fully_valid": true,
#       "n": 1,
#       "scriptPubKey": {
#         "asm": "OP_DUP OP_HASH160 5b157a678a10021243307e4bb58f36375aa80e10 OP_EQUALVERIFY OP_CHECKSIG",
#         "hex": "76a9145b157a678a10021243307e4bb58f36375aa80e1088ac",
#         "reqSigs": 1,
#         "type": "pubkeyhash",
#         "addresses": [
#           "2dhjMcJXJ1n4gemji54vSMS4Ajz7L5HLipK"
#         ]
#       }
#     },
#     {
#       "value": 0.00010000,
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
#   "hex": "020000000101334fb67cd62233ae6adfb4de93ea94c719d5293f991c7420cedfb7291719c3d501000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209abe2f4f8fef2d7bf1d3cddb3373eefdec963d4f6da17629267ea523137008169026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb31976a914a579388225827d9f2fe9014add644487808c695d88ac0bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854086e96db6e173f41d6278a51a58d6f2b79484de159db8f0ea4009320f1522f33be0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b51976a9145b157a678a10021243307e4bb58f36375aa80e1088ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000002710000000000000000002473044022016e926e209d64ee6c0b7cf25308187ec58467f7fa409f04e8b034959580335cf022055e630b9cbfffc25521e5b8909294915c72282a1b349904e0022ee4d1f1133680121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00430100015ee947594fc776ed4088ab23fbf93e425a9f4d8602a16bd5f5286b983a8be6071401a743b106a1b859c0e8327a6c424adaf27c84d7af35342c186e8e43d74a3bfd0c0a601f00000000000000018c66734cd4d11c05e6cc89c5a6e82224dfbeab06a4259590682858aa4bf400d13b97e3f10a1696e7a6398573729619ee282e194be7eb9eaadfa49bb02f3ce5d571a066246e19989a6108678e15d7616613963293a6b30b81e0ce5b69eff2e16c3133531db166e29b226048607c7ff7ca9ae2499d4dc381592ca24bb449b5e67975659064efd2798ed9f6c2f23593c5fcc40692d99ca58971c2625caa67cafc9588307823ab6edd37bdfdb7130602decdfa8fd39fe6d6f8f5df829cf242c9940178dbf4a37df37f4374efe89195e9641b9344a06b8dd6028f57906f6db6a3a928fda81fd2728a352bdef62f79fc1f9b0b53bac6b672925c9dd750827032d3434de9679a63db65afaa4448bdc32e06eb59e662fa8e2c55e14e5a9dd0460e00fac1d5c908b76bc07034e72e837b65321628ea6aa831ac5679afe6f9656c60c471a7e14d25c3791c15fd5f0e2cca354dc34c1f79f228f2ba5f807cf03432803bad9c28f2a9b88537e02f822aa16991b77e3153d78e8bff5d8e224563c157a3c197067a3a93f352a1405039e63923fee925648b5e9782e9a7b6e501131f7d2115ceddf15845a4e3f0f8abc94fbb545a320bd75cec688385c5e19cc68523f413a75fe1ac3eff6c0c71dad43b00c7c2d25be82e2ca32f7364ba6453304b156a65e8a0b70a7cdfe28054e5359fbe89dd94b33b6cfac0f069780f3ff27df7c11efafe31d1055e0f9ecc8976aac5f3ecf1a2734a1fe04b7f1a7ffb4759afe49881a9e3c4a78bee42cb8de5b6b1a8abcdf3d96e3fea119eaf514a7f34e8b71299766fa840cb0c881acb366cb46455c729c84574a166d0197036d75c8c0c6a2861dee915e66dcf5ad8c8fda0972fdaa10a6e0a8a449d7729fb4ab6c5ea1c034f4dc25337a0d71d1b9fbd7aaffe574678f214dbf8ff89bee58c725d5bccdb6d46ba3a8f81e237724d71dd6c156e6cb0a20e18eba07f4aefea5a722be76cc53525216119dd900c9690db506a984d4d681cd338b9495fdd3b580bb79cbbab63d94ba1b644e8aec966014b16a0a05d3c619d626e9a2a33f2ffed4758261c99c1c2cf1c8abcb5c978c6b6a358d8e2fbf5e7fbef92b235e5936fbb95e48e79a29ac45910d981fd7babdc658775e0c040f212aa72ec8a00c6d3ca375276c5c863f03faed550eb6f36339e5aae3751376371f3783108e270ce531bb9820a70283235f5af9d0dbc435a9777463d5ebd6097eb266f07ecdeb3bddb816fa1bad5358e8ab03c80abc155151a941bcf8a0f010cbf501fbd04e59e9d77f13b0dd2c6c4cbfc45b5fbbed59d7ce8e0f8d70e8f673408c1afcdb2deae6c92acc0c882642fa1dc8f97ee4d510d040b696165100d5e0b26dae2d36eb0e2e9b44c7c2aafbbea7fb4d2e7eaff169799c922aec031bea4c209760189069592348bda967cfeaf5d65d0c4eb54d2cbe6d4efded797ee33b389b6b46d9cf524b02d3338d011e354eaa4b74532c9bab8ae29df094de6b8ba749393884e2a7e814a955c2bad1f84ad46d5459c21b2e60b3b484c38a79a3e4c138c5f9312824bd2d1cdc9752a015d5388baa8a64fba041434f4bc0532e7578661c666bb82fdd5df843d156b8984f9668bcc4e0baf6ca0c8db587d2e7b05e98fee818d939b7b398d9d77f7667b67ba33c6666f077f453653feca3bcf11e5d1645c1c7f66784cd6235d1e8f4eec49565d8d86b2eb56ef78d5c59499803a34ea497b257dd4dabe4d92e35fe7d299cdfb724c949e96f5a6c8c0236f2f69339ae6d88ab65c7af9f8cec2ce80230a72cb562643531165a6e8c5d5c4a452f6cfa69c712f3b1f2b74534654a05f2008c2ee74ef1040edb293a4a80977f515024e9aaaba8d7f620f4bdd42ef39b9c62d39f64cee63e4737b38c8f8b35e7406226fb1ad438826650eb9949358179dfd41b5fe3c21bd782a58f1ab5dfbe8370179e905089cf472cbdf7fbb9f84d975f0b8bbee007090cc675463ea2fe2a89ca9f23211230b39b98dac26b2726577825d08442caa93e9a99cebc001a13de294dcf70a3b2d1d927f451b5e5036791234a0c73b7241a3ec0baa2bb9540839cc9aa05de9840e51eed8d9019c3a1e84979164e1031fc44f6c3009670adf92c72bd84f4ecb95eb635b896428d6cc735f9393c1991db26135ee2f3569e46e83e16cfeed59a04183801fe13d66ad0c48e46c6fa2961dbc35a92331540b91bd112dc07a40cf3b927a5535ae184e7aee6d3990dbd52db218883567b8716f21b40e1d999d54fc01b8f56cb1701c9b17fa7e47d5dd68d89462a4efde44a502ffca18964613c762186b17f64170a2a1d06cae7ca151c0323097cdaeac291da16725e97aaf0f6437db3444fedf4223a2eaae7067729cf6bb5a9b75a2caeaff271e5348adc73f9ea77ac7ee850974097c2d0d30acb36ed0fd5f2963b103201eaa9c2614dace01dde7daadfeb6dbeeaba9c8695bf2ce2781d5ec1156e0869613d36fe85dd8a41f1fa6ddaae190562194cd8aa2ed455d2aaf257fadf8b363ab9209725f32d52fbaf7fa07031a030f181b1d1c67d1e1f55837afe61c482dc4c910f0a31cf7c3f10af8f054ba3c47226abe36f0c49acba6df2440b4a02ca27fe798d1b53693b21786160a95117ecbb65c89036ae0688adbb7175aea039bbb2535e04fe5ba9bbae2581b831c6aa5736d705c3a8f6ca28eda077f863d7c55a080ab7a7d408dfafd8dbde03efced55504b6ed65737be568f21584cf23fe56fcf3679ea7aeabfd77646d7714edaf2178b526902df2c3a68c6d96eace6e74822c6fead2211dd0809548938c5284876ca08ce892218026329a256a1c5c33591087acea63fddc041c8eee3d44d382b6a03d69e7336a3850225690960f8606701a7eab98b0930222c2127eac76dd940cecf21d6f570708ef25b223306b3194de9d04ff49e5d646bc7538a682ce45f8a39722a682b80708a8f851a712f119a523e943db80b734b1ff9c24ab4c2ea79b4e564346d7dcfa0fe8e1c2e1377cb3c79cabeff1e4440e69aa07a063e25bceba91413dae78d25eb1b8f90c81ce427b8854427469a3ebd406e613090bf932432b40be990d337b7357afd1060209b6c0cf70878b82fdbaebe2db96bb67623b85f26ed58f0752e3b0ead3a1d5f9d85a06f90bd40474a5c426867737c9a62736ac85904352043dff56fb0a5ab7643502e9eb9928a226e0e70b55ce0bb4c325e3daf1ec92f7b33a2e549d9cab364d2a6d3f7c0a43c5717c1932f3ab6c94f005638066ed963b3a862ef9cd937a5db08ff902ae55c2874a14a491c9273d5cebf509e7687140c1d73a28600344ea28f99f5ab1081a2f4b7e70b348f4aa879a71bdaaf162651bfe3b677dbe2308db11453bfa4d0de20d0953233545a7b6b4dce63be88eac22ebf1aba44009c6f69df1c937c68ca446097fc41784fd946d58d63598c798a0f0903b41358dbc3521dd9dfa409fbf3ae2af68169654e25a3f787bcef96180c5021cacb77b10cc457096f934ddab5719dc8c95451f3e48ebe6050be832cbee0e11a31e6db1d804d67fe749c2f89b14824ce94afa1008453c881978d2596b4753fdf5b8640cf6a0c2dedf5de3e0b4fdc18e0a565228624e25b3758ea8379bb11e4430100016b12126b9240c5ed07aad69fd5d667b56da9a6f24228b6084f0121ad0f405b8df168becdeb216d645eeadef86cf7c7cc7d2250c912e0607d0b0c8f7301ad4a43fd0c0a601f0000000000000001fb2fd5c340109907e6e40b8fa880e8070d7268022ac844e8a234fe02252daae61c5bc0d16cf974ee9851672dc2d48013d70b88d9f8b5a2573309ea7399fbf88de9dacad356e82942caea9485f4dc22f4fa7e2aa453236c889e726afc88949fef26dca9731e3e19c95e0f1c5b246aa9601bcc933220d2b4242fee9a555750816cbf43c6051b9fdd93374e02663fb8fe4893f83af83398743ffefa7208f67cd98d59f91c9b4709f09150585d52467d5dff30864dc17d00915903fb27005a5b3b6c55033aa8ec3ce026767abeaec9cef7d43d1293b4280bb6e44d3c626dc0a5140c62d2b1d33b267005dc58c26c28c5a6e0043ae5b03f156ab4e956412c92a7646c7f1c4134ebef1c0ca3a790f9b15bd4c82747acec139a3ca9d42292f4b2169e05d436779bc0e7a151feeb8ecfd58b3660ea92aedcdb0801b99ec6111493863df743692992e5253137027f0337ba0d06fdde91bed9e90020ad04c4e77f7c5b1ec97a1f3a8781a1068f79f3635b976076a76ceba80fe077df43ca11349d675f9176162dd88a0e58901a1c9e8ed42c87ad01b7b645856e53fae5dadd47a0eda4d09d07492ddc6dbf12cb4d91eae97f424460a2e9ef5fb11896665a19fe9d889fb1129d71f5cd3d2c8851a3f8173be9772b28e3a6f561795ee1e7580e7d55e5cbce15b120906ed85a23710f7bd17a8ec8df58f4e9c9dc1495c3bfc27203d86c6b94973d2256840face2c1b6b7e4fdf081d19ba97c4620a059ea295641c53da147d68dd48a0223894b660282f53a78caac10819e03eb346499d0c5b11912391d87da1af7d5c57c2ce772586bbc11656ea32b1f2168dae8e91b0d202a8b38f0442b9c3e97cbdfc1493915e08c216510a0b81b5ccffed9a8ca966b60fc08fa14baf9ea6db8270843d475ece05c29aa4789ffdae6ca97d5b544699ce4e071dce504f8f619d7a6edecccdb56ae8b98da82bd4bb24150fc8c7a5f86c42d8982e285879e1412813a9c7dbfc445566e66fc3380dbdc837594175e44db7b355ea447499bad991e2c042366fa3a84ef260382d9ffb18494b29c0574f5495a1339586b15c2f8d4117fcdc7e0c5e81927773b1f712e34f11555b01f398401619f46334245e1879e741f9fac327cac8adf1c3335d6881f25d9dea1972b1e691438185f14e5d6b271f708cd95d071c32ccf8d22fc02f49052b46b5dfab9581f30d2a4226990ee308655918d3e95043dc0a2e1894a9b048cb0d4ef6e4d1af82306f139a319b533b7f75a641c0516912b6ec33aaefdfe4e7e1ae9c44681251ebe6a4232248115d8f52b099e079d126396129890338ba8b9025db620d87ed64652aac40d2f19289e16063d1ad468e4056b22fa31541a9a24b748354658ff94b4d9919e1d7b7ca20a52066eb27e5577f553c7b6f423640d909e0b53d0e3094cca8173b0a070c44cb76a113e0778f5901005e748d448f2e67d5067d3a729cca475c64a4cf02333bdb47bd6e4b343895a29f0082347b114d9d0128150d976bbb8bac695d4f6129a7ffb332f7c9ec26187f4b14f273f4a71fc4bfb7edf61a1d059cf3855e092755eac429fb9789a93c7eb1cefa030ada3bcecb22d0a824a25cbadcf64a675a67fc3197d3770c67cddf0607a0fe796c412fa161a6057b37230668fd4839aa1881f28a0e6761980915f111e2485e64a3a4927c920a194197574a476fb92d559618b02a35f671ccdfcf517ea377a37daf97a39946bbb985e22207da1b9991dd269875e2e60704d5221cd089cc29decd21f4671f26ccd78048c52384242f90cf3cca6ff2e29ead099abe0f5036590831589b4b2ef45a1475884258019379547a00dc2370dbb254136a91384c66796f35034863fcd970e0f779a189d95d5fdc5bafe9b60f73bce531c81cf16b7f42a08192779619aa5686f6637023268d67054df86dffaba4089c8a5a28e0cc1825f92b35b4e8d8e3916bf15cd07122e39a8dc0f73646ed154f18136b8c2c58fb25ff934ea30347b64b49d624eecbd529a4a2e46a8a1768da22ec6cc9117777d9084079aadfb9584ab8ee105ac51c1739e0abbfcdc848969279b78ad56d47bf3cea2e7c91a03026540d40703400316914a69565a444d4bcaa1b88f76fd694907b7c2c7d38ec67488ee3ea9c47d29356fc26182af559e5d9fc194d6b1e808b201474e8e5f3dbc03760861da931df413c877d8dab9c5724f4528545d742689396b90df65819f46d5005c5eb44044090c1806d1f0d96d04887caa33b2fafa6a97f83ca934da1cf38b526f3d421bb2610433e988fbe30124b0fab47b42e8c484a495a978e93191658d2b00019285e6a6c2cbbf5b351db312971048fcc51f6fc3289f6a2b0a8cf993d4a55274dcbd07681f49302ac1bed7cec0da1dcafe73b6c9f11ed893545ce9c40805b56074a7a5696c58c09211a37602ed4dca664f614580e3bfd3f87d93bdaf0c797ff38d2ed035f0fdff211f6604a6431a4476bcf0898ac850a651ed61b5d80ffad707f7e65cd41f0580cdc9b73444019f2cbc12196427e54623843405f9cecca313e062721fcb10081257c324a925a54cf01194c7691cc391b2a3b351540c114705e6d58d4f9289582f388f058da763d29eced2c1c4f1b4dad2d0c115953e6d20fab1c00080ba2eea2b6c75b090ccb34750c3f953de1bdc008f6bbb6548571d0e34e02c6e745275820de2f4f5e7a05153389bb4ccefea30d94d3361aa3f5b69eb272890be84643662407fe590a26beaf265acde68c856bdae86878bafb3c0f9ff60afbff027dcd99be965c24e27487bdecb03577c4ee684aebb8a1178eb7afd5da4c00dff8a7dc233b384b867ba3b8017c1c65903df441807983b5767576c00d208a6dcbeefa1e0dcf45b1ff6c009d4074a1f28ea8203cbdc53ededbecc317f056efa3af01b560430345c5a5dc8e3f8e5bdba83c4d394923b1a5c82a4893107172137390b01ce1ce58c3dcd1e7fe9bb2fabb73250d57daae59c1e36e94f36d968fc5204c21351f5590430a575c92d1160d4c6818891983b9dbc0d01f376043dc28543b9c1ac950481bdafbe155c42e8f63ddce31c49b03cc655bb6bb31c039f5d5276f9f64c6508f3e387f2375bc864f31f10fe8284e97f449e60429cfd000a7404f6bc256bf3de65fed81aebc902e34cb9f6eda5e2209fc35475f04d39d885d95343f8bc73fab1220efba793ba9b6b09f4a912951e2c3853d8d3de266d34b39e3afe9859d1a4a0152e070df567738256e59e7b3478c3e929498c187612d75902d9fb40b539c004c12fe3dec663782eef818a1d1d34d8eb4de6e5bf4a6616d2fd036a947a6abee720dfdd1f2c1ed450ebd3e95b145e2f865a14e076b455ef5288dc38dffa14cc6fd5be58bd2b87a9fea886cfbe739fec109a419775151d38e0774b7d091aa2280cb0e07555321806a97e519f72f59f105d3a1fbe64427e763e2f3e0d9f59ffc7edbb1582b820d73d80931f125500dacaa23131eba98e7feccc7b88287c47896a18a6970aa5956a3dd6cb053c349392cc2b0343472e7dd332a55ececfcef5de4a3ec78eba9f8ec5fc08de031cf5bb385292c241a5b10814270a72ffa5cd9f258bdf000fbd1648107443774e6376ba85d60000",
#   "ToString": "CTransaction(hash=434c8afb19, ver=2, vin.size=1, vout.size=3, nLockTime=0)\n    CTxIn(COutPoint(d5c3191729, 1), scriptSig=1600140099a7ecbd938ed183)\n    CScriptWitness(3044022016e926e209d64ee6c0b7cf25308187ec58467f7fa409f04e8b034959580335cf022055e630b9cbfffc25521e5b8909294915c72282a1b349904e0022ee4d1f11336801, 033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=76a914a579388225827d9f2fe9014a)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=76a9145b157a678a10021243307e4b)\n    CTxOut(nAsset=b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23, nValue=0.00010000, scriptPubKey=)\n    0100015ee947594fc776ed4088ab23fbf93e425a9f4d8602a16bd5f5286b983a8be6071401a743b106a1b859c0e8327a6c424adaf27c84d7af35342c186e8e43d74a3b\n    601f00000000000000018c66734cd4d11c05e6cc89c5a6e82224dfbeab06a4259590682858aa4bf400d13b97e3f10a1696e7a6398573729619ee282e194be7eb9eaadfa49bb02f3ce5d571a066246e19989a6108678e15d7616613963293a6b30b81e0ce5b69eff2e16c3133531db166e29b226048607c7ff7ca9ae2499d4dc381592ca24bb449b5e67975659064efd2798ed9f6c2f23593c5fcc40692d99ca58971c2625caa67cafc9588307823ab6edd37bdfdb7130602decdfa8fd39fe6d6f8f5df829cf242c9940178dbf4a37df37f4374efe89195e9641b9344a06b8dd6028f57906f6db6a3a928fda81fd2728a352bdef62f79fc1f9b0b53bac6b672925c9dd750827032d3434de9679a63db65afaa4448bdc32e06eb59e662fa8e2c55e14e5a9dd0460e00fac1d5c908b76bc07034e72e837b65321628ea6aa831ac5679afe6f9656c60c471a7e14d25c3791c15fd5f0e2cca354dc34c1f79f228f2ba5f807cf03432803bad9c28f2a9b88537e02f822aa16991b77e3153d78e8bff5d8e224563c157a3c197067a3a93f352a1405039e63923fee925648b5e9782e9a7b6e501131f7d2115ceddf15845a4e3f0f8abc94fbb545a320bd75cec688385c5e19cc68523f413a75fe1ac3eff6c0c71dad43b00c7c2d25be82e2ca32f7364ba6453304b156a65e8a0b70a7cdfe28054e5359fbe89dd94b33b6cfac0f069780f3ff27df7c11efafe31d1055e0f9ecc8976aac5f3ecf1a2734a1fe04b7f1a7ffb4759afe49881a9e3c4a78bee42cb8de5b6b1a8abcdf3d96e3fea119eaf514a7f34e8b71299766fa840cb0c881acb366cb46455c729c84574a166d0197036d75c8c0c6a2861dee915e66dcf5ad8c8fda0972fdaa10a6e0a8a449d7729fb4ab6c5ea1c034f4dc25337a0d71d1b9fbd7aaffe574678f214dbf8ff89bee58c725d5bccdb6d46ba3a8f81e237724d71dd6c156e6cb0a20e18eba07f4aefea5a722be76cc53525216119dd900c9690db506a984d4d681cd338b9495fdd3b580bb79cbbab63d94ba1b644e8aec966014b16a0a05d3c619d626e9a2a33f2ffed4758261c99c1c2cf1c8abcb5c978c6b6a358d8e2fbf5e7fbef92b235e5936fbb95e48e79a29ac45910d981fd7babdc658775e0c040f212aa72ec8a00c6d3ca375276c5c863f03faed550eb6f36339e5aae3751376371f3783108e270ce531bb9820a70283235f5af9d0dbc435a9777463d5ebd6097eb266f07ecdeb3bddb816fa1bad5358e8ab03c80abc155151a941bcf8a0f010cbf501fbd04e59e9d77f13b0dd2c6c4cbfc45b5fbbed59d7ce8e0f8d70e8f673408c1afcdb2deae6c92acc0c882642fa1dc8f97ee4d510d040b696165100d5e0b26dae2d36eb0e2e9b44c7c2aafbbea7fb4d2e7eaff169799c922aec031bea4c209760189069592348bda967cfeaf5d65d0c4eb54d2cbe6d4efded797ee33b389b6b46d9cf524b02d3338d011e354eaa4b74532c9bab8ae29df094de6b8ba749393884e2a7e814a955c2bad1f84ad46d5459c21b2e60b3b484c38a79a3e4c138c5f9312824bd2d1cdc9752a015d5388baa8a64fba041434f4bc0532e7578661c666bb82fdd5df843d156b8984f9668bcc4e0baf6ca0c8db587d2e7b05e98fee818d939b7b398d9d77f7667b67ba33c6666f077f453653feca3bcf11e5d1645c1c7f66784cd6235d1e8f4eec49565d8d86b2eb56ef78d5c59499803a34ea497b257dd4dabe4d92e35fe7d299cdfb724c949e96f5a6c8c0236f2f69339ae6d88ab65c7af9f8cec2ce80230a72cb562643531165a6e8c5d5c4a452f6cfa69c712f3b1f2b74534654a05f2008c2ee74ef1040edb293a4a80977f515024e9aaaba8d7f620f4bdd42ef39b9c62d39f64cee63e4737b38c8f8b35e7406226fb1ad438826650eb9949358179dfd41b5fe3c21bd782a58f1ab5dfbe8370179e905089cf472cbdf7fbb9f84d975f0b8bbee007090cc675463ea2fe2a89ca9f23211230b39b98dac26b2726577825d08442caa93e9a99cebc001a13de294dcf70a3b2d1d927f451b5e5036791234a0c73b7241a3ec0baa2bb9540839cc9aa05de9840e51eed8d9019c3a1e84979164e1031fc44f6c3009670adf92c72bd84f4ecb95eb635b896428d6cc735f9393c1991db26135ee2f3569e46e83e16cfeed59a04183801fe13d66ad0c48e46c6fa2961dbc35a92331540b91bd112dc07a40cf3b927a5535ae184e7aee6d3990dbd52db218883567b8716f21b40e1d999d54fc01b8f56cb1701c9b17fa7e47d5dd68d89462a4efde44a502ffca18964613c762186b17f64170a2a1d06cae7ca151c0323097cdaeac291da16725e97aaf0f6437db3444fedf4223a2eaae7067729cf6bb5a9b75a2caeaff271e5348adc73f9ea77ac7ee850974097c2d0d30acb36ed0fd5f2963b103201eaa9c2614dace01dde7daadfeb6dbeeaba9c8695bf2ce2781d5ec1156e0869613d36fe85dd8a41f1fa6ddaae190562194cd8aa2ed455d2aaf257fadf8b363ab9209725f32d52fbaf7fa07031a030f181b1d1c67d1e1f55837afe61c482dc4c910f0a31cf7c3f10af8f054ba3c47226abe36f0c49acba6df2440b4a02ca27fe798d1b53693b21786160a95117ecbb65c89036ae0688adbb7175aea039bbb2535e04fe5ba9bbae2581b831c6aa5736d705c3a8f6ca28eda077f863d7c55a080ab7a7d408dfafd8dbde03efced55504b6ed65737be568f21584cf23fe56fcf3679ea7aeabfd77646d7714edaf2178b526902df2c3a68c6d96eace6e74822c6fead2211dd0809548938c5284876ca08ce892218026329a256a1c5c33591087acea63fddc041c8eee3d44d382b6a03d69e7336a3850225690960f8606701a7eab98b0930222c2127eac76dd940cecf21d6f570708ef25b223306b3194de9d04ff49e5d646bc7538a682ce45f8a39722a682b80708a8f851a712f119a523e943db80b734b1ff9c24ab4c2ea79b4e564346d7dcfa0fe8e1c2e1377cb3c79cabeff1e4440e69aa07a063e25bceba91413dae78d25eb1b8f90c81ce427b8854427469a3ebd406e613090bf932432b40be990d337b7357afd1060209b6c0cf70878b82fdbaebe2db96bb67623b85f26ed58f0752e3b0ead3a1d5f9d85a06f90bd40474a5c426867737c9a62736ac85904352043dff56fb0a5ab7643502e9eb9928a226e0e70b55ce0bb4c325e3daf1ec92f7b33a2e549d9cab364d2a6d3f7c0a43c5717c1932f3ab6c94f005638066ed963b3a862ef9cd937a5db08ff902ae55c2874a14a491c9273d5cebf509e7687140c1d73a28600344ea28f99f5ab1081a2f4b7e70b348f4aa879a71bdaaf162651bfe3b677dbe2308db11453bfa4d0de20d0953233545a7b6b4dce63be88eac22ebf1aba44009c6f69df1c937c68ca446097fc41784fd946d58d63598c798a0f0903b41358dbc3521dd9dfa409fbf3ae2af68169654e25a3f787bcef96180c5021cacb77b10cc457096f934ddab5719dc8c95451f3e48ebe6050be832cbee0e11a31e6db1d804d67fe749c2f89b14824ce94afa1008453c881978d2596b4753fdf5b8640cf6a0c2dedf5de3e0b4fdc18e0a565228624e25b3758ea8379bb11e4\n    0100016b12126b9240c5ed07aad69fd5d667b56da9a6f24228b6084f0121ad0f405b8df168becdeb216d645eeadef86cf7c7cc7d2250c912e0607d0b0c8f7301ad4a43\n    601f0000000000000001fb2fd5c340109907e6e40b8fa880e8070d7268022ac844e8a234fe02252daae61c5bc0d16cf974ee9851672dc2d48013d70b88d9f8b5a2573309ea7399fbf88de9dacad356e82942caea9485f4dc22f4fa7e2aa453236c889e726afc88949fef26dca9731e3e19c95e0f1c5b246aa9601bcc933220d2b4242fee9a555750816cbf43c6051b9fdd93374e02663fb8fe4893f83af83398743ffefa7208f67cd98d59f91c9b4709f09150585d52467d5dff30864dc17d00915903fb27005a5b3b6c55033aa8ec3ce026767abeaec9cef7d43d1293b4280bb6e44d3c626dc0a5140c62d2b1d33b267005dc58c26c28c5a6e0043ae5b03f156ab4e956412c92a7646c7f1c4134ebef1c0ca3a790f9b15bd4c82747acec139a3ca9d42292f4b2169e05d436779bc0e7a151feeb8ecfd58b3660ea92aedcdb0801b99ec6111493863df743692992e5253137027f0337ba0d06fdde91bed9e90020ad04c4e77f7c5b1ec97a1f3a8781a1068f79f3635b976076a76ceba80fe077df43ca11349d675f9176162dd88a0e58901a1c9e8ed42c87ad01b7b645856e53fae5dadd47a0eda4d09d07492ddc6dbf12cb4d91eae97f424460a2e9ef5fb11896665a19fe9d889fb1129d71f5cd3d2c8851a3f8173be9772b28e3a6f561795ee1e7580e7d55e5cbce15b120906ed85a23710f7bd17a8ec8df58f4e9c9dc1495c3bfc27203d86c6b94973d2256840face2c1b6b7e4fdf081d19ba97c4620a059ea295641c53da147d68dd48a0223894b660282f53a78caac10819e03eb346499d0c5b11912391d87da1af7d5c57c2ce772586bbc11656ea32b1f2168dae8e91b0d202a8b38f0442b9c3e97cbdfc1493915e08c216510a0b81b5ccffed9a8ca966b60fc08fa14baf9ea6db8270843d475ece05c29aa4789ffdae6ca97d5b544699ce4e071dce504f8f619d7a6edecccdb56ae8b98da82bd4bb24150fc8c7a5f86c42d8982e285879e1412813a9c7dbfc445566e66fc3380dbdc837594175e44db7b355ea447499bad991e2c042366fa3a84ef260382d9ffb18494b29c0574f5495a1339586b15c2f8d4117fcdc7e0c5e81927773b1f712e34f11555b01f398401619f46334245e1879e741f9fac327cac8adf1c3335d6881f25d9dea1972b1e691438185f14e5d6b271f708cd95d071c32ccf8d22fc02f49052b46b5dfab9581f30d2a4226990ee308655918d3e95043dc0a2e1894a9b048cb0d4ef6e4d1af82306f139a319b533b7f75a641c0516912b6ec33aaefdfe4e7e1ae9c44681251ebe6a4232248115d8f52b099e079d126396129890338ba8b9025db620d87ed64652aac40d2f19289e16063d1ad468e4056b22fa31541a9a24b748354658ff94b4d9919e1d7b7ca20a52066eb27e5577f553c7b6f423640d909e0b53d0e3094cca8173b0a070c44cb76a113e0778f5901005e748d448f2e67d5067d3a729cca475c64a4cf02333bdb47bd6e4b343895a29f0082347b114d9d0128150d976bbb8bac695d4f6129a7ffb332f7c9ec26187f4b14f273f4a71fc4bfb7edf61a1d059cf3855e092755eac429fb9789a93c7eb1cefa030ada3bcecb22d0a824a25cbadcf64a675a67fc3197d3770c67cddf0607a0fe796c412fa161a6057b37230668fd4839aa1881f28a0e6761980915f111e2485e64a3a4927c920a194197574a476fb92d559618b02a35f671ccdfcf517ea377a37daf97a39946bbb985e22207da1b9991dd269875e2e60704d5221cd089cc29decd21f4671f26ccd78048c52384242f90cf3cca6ff2e29ead099abe0f5036590831589b4b2ef45a1475884258019379547a00dc2370dbb254136a91384c66796f35034863fcd970e0f779a189d95d5fdc5bafe9b60f73bce531c81cf16b7f42a08192779619aa5686f6637023268d67054df86dffaba4089c8a5a28e0cc1825f92b35b4e8d8e3916bf15cd07122e39a8dc0f73646ed154f18136b8c2c58fb25ff934ea30347b64b49d624eecbd529a4a2e46a8a1768da22ec6cc9117777d9084079aadfb9584ab8ee105ac51c1739e0abbfcdc848969279b78ad56d47bf3cea2e7c91a03026540d40703400316914a69565a444d4bcaa1b88f76fd694907b7c2c7d38ec67488ee3ea9c47d29356fc26182af559e5d9fc194d6b1e808b201474e8e5f3dbc03760861da931df413c877d8dab9c5724f4528545d742689396b90df65819f46d5005c5eb44044090c1806d1f0d96d04887caa33b2fafa6a97f83ca934da1cf38b526f3d421bb2610433e988fbe30124b0fab47b42e8c484a495a978e93191658d2b00019285e6a6c2cbbf5b351db312971048fcc51f6fc3289f6a2b0a8cf993d4a55274dcbd07681f49302ac1bed7cec0da1dcafe73b6c9f11ed893545ce9c40805b56074a7a5696c58c09211a37602ed4dca664f614580e3bfd3f87d93bdaf0c797ff38d2ed035f0fdff211f6604a6431a4476bcf0898ac850a651ed61b5d80ffad707f7e65cd41f0580cdc9b73444019f2cbc12196427e54623843405f9cecca313e062721fcb10081257c324a925a54cf01194c7691cc391b2a3b351540c114705e6d58d4f9289582f388f058da763d29eced2c1c4f1b4dad2d0c115953e6d20fab1c00080ba2eea2b6c75b090ccb34750c3f953de1bdc008f6bbb6548571d0e34e02c6e745275820de2f4f5e7a05153389bb4ccefea30d94d3361aa3f5b69eb272890be84643662407fe590a26beaf265acde68c856bdae86878bafb3c0f9ff60afbff027dcd99be965c24e27487bdecb03577c4ee684aebb8a1178eb7afd5da4c00dff8a7dc233b384b867ba3b8017c1c65903df441807983b5767576c00d208a6dcbeefa1e0dcf45b1ff6c009d4074a1f28ea8203cbdc53ededbecc317f056efa3af01b560430345c5a5dc8e3f8e5bdba83c4d394923b1a5c82a4893107172137390b01ce1ce58c3dcd1e7fe9bb2fabb73250d57daae59c1e36e94f36d968fc5204c21351f5590430a575c92d1160d4c6818891983b9dbc0d01f376043dc28543b9c1ac950481bdafbe155c42e8f63ddce31c49b03cc655bb6bb31c039f5d5276f9f64c6508f3e387f2375bc864f31f10fe8284e97f449e60429cfd000a7404f6bc256bf3de65fed81aebc902e34cb9f6eda5e2209fc35475f04d39d885d95343f8bc73fab1220efba793ba9b6b09f4a912951e2c3853d8d3de266d34b39e3afe9859d1a4a0152e070df567738256e59e7b3478c3e929498c187612d75902d9fb40b539c004c12fe3dec663782eef818a1d1d34d8eb4de6e5bf4a6616d2fd036a947a6abee720dfdd1f2c1ed450ebd3e95b145e2f865a14e076b455ef5288dc38dffa14cc6fd5be58bd2b87a9fea886cfbe739fec109a419775151d38e0774b7d091aa2280cb0e07555321806a97e519f72f59f105d3a1fbe64427e763e2f3e0d9f59ffc7edbb1582b820d73d80931f125500dacaa23131eba98e7feccc7b88287c47896a18a6970aa5956a3dd6cb053c349392cc2b0343472e7dd332a55ececfcef5de4a3ec78eba9f8ec5fc08de031cf5bb385292c241a5b10814270a72ffa5cd9f258bdf000fbd1648107443774e6376ba85d6\n    \n    \n"
# }


def get_confidential_address(client, path):
    return btc.get_address(
        client,
        confidential=True,
        coin_name="Elements",
        n=parse_path(path),
        script_type=proto.InputScriptType.SPENDP2SHWITNESS,
    )


def get_address(client, path):
    return btc.get_address(
        client,
        confidential=False,
        coin_name="Elements",
        n=parse_path(path),
        script_type=proto.InputScriptType.SPENDP2SHWITNESS,
    )


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_p2sh_confidential_to_confidential_sign(client):

    in_path = "49'/1'/0'/0/0"
    in_addr = "AzpuzTFTuET7YqJ9U8fBuRTf5xvsLmudLg3uvycfP1aTFpKXUYuUs3kz98boyzDSe5n1MevURZdB4pR5"
    assert in_addr == get_confidential_address(client, in_path)
    assert "XNW67ZQA9K3AuXPBWvJH4zN2y5QBDTwy2Z" == get_address(client, in_path)

    txins = [
        proto.TxInputType(
            address_n=parse_path(in_path),
            amount=10000000,  # 0.1 LBTC
            prev_hash=bytes.fromhex(
                "1584e36929695f64cc2a153329dab3173db9f88021be370f55da9f0916576078"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        )
    ]

    txs = txs_from_hex(
        {
            "1584e36929695f64cc2a153329dab3173db9f88021be370f55da9f0916576078": "0200000001015e036a728bed872612abcbfe7ae1bddb3b6ae4c0ae27b4742826925ec2f57cda01000000171600142b9d3f2fe4c4bb18fac607498694a087b0b77d8dfdffffff030bc86b067953f68d14c0b56a15f885417e23faace10b35ffb29e2033a3e8fdb41b092d758fde9cfc3f6e50823ccffa3dcb3e1edce17e12a3bf0b18132fefce9a993d021361afa71d33ac76ed03138b70a3219e0c05087e356add31ae3a890c320e1f1417a9147a55d61848e77ca266e79a39bfc85c580a6426c9870be545bf3f10bff93576ea5854f88f3ccdd684116aff23d07f813b42b09a06183209c50e44f85d1ab59ceda282639eadfc1bfcf170d8a1707e098e709cf40cebe8ff039727555e1349254903de9df2ebe71145fadccba5de9d5f3ae8878e7eae4372a717a914bde3477f754752ab937069437b314f8361b577a98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000aa5000000700000000000247304402205434d4f71365eb044cddc6b90472256597d203485073073dd9f95f1ef29731f802204ddcc8b36a92b4f58f1f76ffd2444fef6e85887759e7cf5aa710e6126d4ab6320121026de9c2e89aaf6ab280b06afa1892216f8fbb24405f057c167c5e3e16fd6f238700430100016cbd3a3c756e261afd00e762cd598ff2ce59a53c9f939d0d2be889368d6111ae4d71f22e7fab4a97c3709cfb157463517023556a9841d04763ecff0dcdb56dbcfd4d0b602300000000000000019be900e19d596b56a3074de31f19f0f317e11f3c8694eb7682ef78e4d6ebd8a06a6827559776fc1447151e850cc7d23cbcde87dbd0f01d9082e2b0181e0b1756b2f259c099d07378c6d8888ad8ee09f0a1d67142af7b955b008d9eb4a5e17bd13585f2eaa50dbddf4f5d13dfe2bcc67cfefe9d1bc67d42f7f5739c5dff3594b0e04bdfce17b2fa73baba6270728a1309f2bc77316aee7765712daa8a97d3c5eef32d5ccd87356b02be2f98c637738bfe87193708bffa0212ceae985f698fc0721a2f0c18447c5d49e8a149d02ac99e4e098889c145be5c34308f4beee9dadcc9212e7092ba36c59dc14fef957f73ede31ef0ed4dc9269354af7060679e8c9ffc672adea6a9eff809fe211b4ad530a8c157acc8be93fe7177e8d6058a4b41dce600d830622b44df3b7543a241becc7d68c46a8ea34ac354b226029be853a81244208d6d32935f0068ed45b568eb1ee7a2a8948eb7625a4e4989df8cb0202718e102c5eb7451c6acf59c17094e257e7475c756827f6d89b11bafd0b755537d537bd91c3a6d0d19f8b0b68c29bfed8a7570d2599c83eba75aaefe4fe76803d7b719cf8b8857e9714bdf705d13cfab05d73517f3beda8d177c6652e445962a3a010dc8730dcc80bd80802d7a9606155cefb94bc5e096b2bc5c29c1c1a42b87b282dd29311c8591943884ebe0cd80b58b0c8f1c26739ace59e7a537dd8ebbef3eaf89e8a326592b361c108dc5c2bc7eabe0c33220e6d1951ca6d625a720f3869d0aef1d768a96337fb7307d415e056e819a5c43d5dda4dbc946a49a5ff11c5c8ad7ec4373c0854dc2c653a0d9f4aed34f3c281d0b820b1e56080833d5a99654b7ac6575f0cffff64ab9ab9f75d3b8022ff48215abfe8d258719e80b8ac5b336c0e1a2527c5fb84b486a4058ab45c2e1cae4b33b08e93f71e5a81c556b25f1867baec7ea6d5718ed79faf43850895704362b09415c662c23dcf47be27da1a3037433092f2f7e22bd806a502eca08061696039d46b1f540813c8e22d2f6abd93a8a9caae5d28a9a376350acf7cde9b337d6bea387f2909c5bff95b0a24c5f10912ab739647c7c82442d570789927ea7737193b14c67100b35ac5f5ee5db03dd8f55e6c79494d2d14a989fc4c8c5599bc207ebc21b9338cf60cf7b4074279a17509be7e6b1c4e98b0ca129f2185c021492015ddce1e5dce94f3142baf37313dfc37d436e4c643029ea030655ac3ee87d6e891badeb8bdccb4a070b4280aef9d574dc7c2ea5dab1c0f253749ae985302ae997ab696723808559c937fc6d3194588cb2ad9d4a4955f98933b75beedeeb60287de610799a997ee865132377461a721d8675c84f77d9003ddf9d09ccf2313c3f640466f595ca8b2a77c4c34313c97eea1e429244109aa535c092b03d9c49a8075ccf2debb119de800689859bf7bae6342a1088256f3193113be87f560f223e6d06ab5c4dc361ffd615a64eae69458a95df71d4b6016ee95b0448d5a1c2867134536d2c21765c555e9e92df3b1fd08f34c132eb7e14e431e598f73bf9754964fee36ab6ea466b43f183650cd62acfe6fe247287d4077530eaaeaa5af5d085f27cdaaa53541f7a0c965de0673acb742acc051872d70f71d4b61e9c92c792e7b0b08293a75a2bdff6e07f3945f3440102a8514ec0247cf95ffaa620c1e36c309f842faf20d70cd77038b1d0415bbf73aedd270da1f34c7d7949f6220f2ab3a54166dc4b4733da99a52495b56b019bb372987f3223dee5b582f7e2afcb07ca8eb396378097d7a15fc970589203a05ba2104828af5ac130fc2656262a766882adabce8f0f72e7efaa1d892f73b75f76aa3155ec8a9fd60f3d6c807802cb6ebdda1ab59a1e6bd29bfd0b1a7bc23b6dbe1e78dfc4eb2b6a431e3d7a63bdc96655e0d60e2b188aff369f8bda4300d368077cdfe08488194e9e87cf4e131400630a243be818d2929ca6de81664be050aa3252f3a73605b05c8ae4f2f9127aaf6ffa39a309c3fe9b76986cce766fe1fe6ae7e463ee3c9bc7fe31a535bb59d1e9996407a9164d1fab8143abfd0ca605392160090c53caee54af88b819df5119dba8cbce7a46d7561baf424ef96b28a097cfe5accd47780e02475f6ce190029cb639c737c14b78f5215ac04ce81e5df50e5ac3451cf12d0bfa37dce1463abfb01e1881781468d514edcac9e481b722e664d7a0511f1d9a4a9603a94141cf0827cff8a8dbfa0d1072a420781af061c40cf257c96def5485b3470298ef40b1e22e82cbe5779153f69c88518d60cb91b34a91b5d3d1063d7a722b73ab4624e4dc26471f7e8e76b68cbbe0429aa029d1c58007b244ae769f12e34e55836762915201cfc4043ccbd293b50b62dcd9862cdc34e4374ddc858abd2de5d95b33eec417c56a629157680be796ac5f49f0128ed46d5704c2fc8bed9be267229aee1afe39cc1fd7d80fd4a236b2712b77ddfc522a8bf2c6607bf43db65c8d16e245ba87717c7ed2db08fe338dff95836ac8280196b36a0a422ec7aaf479afd7fcf8c17c4d560ffe6f0a0eaeaee1c03f8f7b226186fe1f2a399419f6e61c564d775b6235690f86627ba2c5a1e7c9ec438172ab2b24408eccd8c842f4ede2e078b89d024be62980d0700b8d4a920f8cfc6030839988965bf9b1f172dc9b52479a042b20e6279b807680ebb5ac7415e753593eace8b14789377943c262e1951485324f7005bfffb9759c0ca759e1100e632818394f255e4785717b3cbd51b496e4b304a1a465778135ef0978556830c99b10044d7827a07d9db374ae294f48438367454594cd0a7a7cb10b2aace45936a4a767617a00faa58f233dd2272c2e0e2af6dc2884d819cf0f455c81147b59fc187c40770a4f8fa6d23e5715f361681820d01419913c54dcb9b1a9777ba3370592f1583bf313577f438788a3c5a11db615d0227b5a61a4ab2c2fb194bba66ffa0b5e4015477342ba90abf2a51a2a3002cdb187b5c26f73e9eab8632089593190558a017695035bea98f12e540a045940b61c064e73c3c2bcff8afebe12dc1838c3c6c2df7e4e1fc412c2fceccb736696ff6c792813704a0bea52dea4a2c92eae30c256bec954dbf1b97ed8cc1b73094edb2d13b599fc9680a4eb206763dca192cfbc594ff7bf21c1c6c404c3b28f9ae51ac1022d0707625d2edb19db6affcd28da1aa3261a040165b7d112dc7fe3e70f743e57f17bece01c6e390293e97d20b1a344d296cec88545b7ebd9009415ef264bfaa374ad00373eea364e92c558fc6307a03ab77280f9f94d98b288a9fa7916018912ffebfee09b34254eefddc43c7cd25ac796b8fa7d062e8d8546ce8f9a02ca46768f291941ec803ee5e609cc3ecda6b34ba30fb2cd8c78ebe60ac5ab2dd49678ef0fd243dcbb39e9debb0fdfa154471fc3b09ac86ba114d9272b8da061d17af84e3c0b4a955beee9ed0dc8bf52c64516033ec378df35742a2786bc0f47c30b05fa495af53ca8d6f164ada6c9f248091d4a91668b7cbf84aa3651bf652c6394f09f5901d3747323cf5ec391953918b001c0b65b3e3228132943fef1718310018fa604e10c6aa89c20092fdc037537226fec9479ebb877d3ac10bd98937993d24d807f0173a473101c9aeddefd8a62e9290a868b53bf939d0e57d9de1cc858a9c41b3622f2ed182855795415ba8d98fe6e0cb0fc61a4aeb9f70babefddfa929faa2595c43254c3ce7378f26d5cdb7edd59f9d551fcc3a1d90f3fda663a563823f67e0045ec707469ce63a5b3529fc77e3bd53ac8ddfcc2aa8a349ed5206de20d10a41bcb1e37ca3f64fa0ba9b6286763941b1bdff4fac9d0a1233c267c07ef1fd12325c76860936cc94da2b7c7cb2d8ee41688e173d5632967b065bb49c650038db2fb9d28828fcf223fdc980f1d209c3944358c39c0d4953a032111884b5a797d6c2ac9fbc0e393304f36a642adbb10a0133fb856887b209b699a0726059bcad3d46555c553fc6eaf8a38732d59817e8da153589314b05878d88ab791ffe777d1cd5936373c16ec1574fe84976a436a5c93fae8105d1f86b8ce0ce5fb1445122d3b430100013d590d9c5345f913ec1b2cd6e72d8f1253cc20b238b881bc0bfab52fa7526f3260c8c47f69963ddd752b166ee1ea87d4a2871b1e82d158ce14dc4ea7f4776150fd0e1060320000000000000001847e5a019e23c4a9b2a7c48a277170275517630693aed3d613b68320a7b40666fa3729a34d7e7f4453446ddc9df9f58c164dbdb54887a08a4f6647b28089b4d32c3dd36a4435da94607a86b94468e7b2553a6cba4179bdd49fcfe201e615e16f8370ff2e4a009bf4ba4ed24057a1e7fe8aa3dc2870ec4aef04f9d3b078e200fbe584b23295270f6236322eda8cdd025433bd7408e7e8a0ad09608823fb27cfadc448c6ac32b6c50be9aabe9fc46a7889a459dad5ff1392c8a08d4f0a4d1c99d7072fa13cf283748b692bb49ccaa41522e5565213f8a3277f14bd01c3647da40f6aa84d54246de23359f426c7892e773a0eb66173225b29fa8d8f567d6925a1545fec8c1515c80fe49266bb22648b8338238a0d16d471fb11640512ccf04276ffa88eef2fee3d84d28a87c563a15b0dc42236954e89dbbcce5c61033264daca51335fea82f59294c89152aaa46c4e74861ec99d7293fa90437c6ed1950f0b93fc68452d0710f0456dfa1d86c947f9ef29fe0763f21b16a773440f1e942630b4d110d1672e53a7647ec1c6da87c0420ca348977e679ef1b046580f63372de6c008710cd24ed519d79285373661603ea9ce460b1bc62b83e249fa1604cc3d1fd6bb15191eb59435dba24f923f71ce249e9ecb76cea24c1ec4f493ed339ac46f449ac06d37c9034d720516ddadea8da0cfd54cf42a8e3f1777819639cf80310edaabc0f25e10d4e6165e69965174ff907ac843b0afd979693d0e02ea72fe0b2c1d5323b1bc324c078eac36398dc6127bf738e392b0d8b587d165d2150dc36b3133a36f069a41057f64339d65b3214de39ec13574020d0ba02a064580b5d9d0adb8142de13b8e65784735ab8766fd6152494f2446c50a181151177309a8f1390a7cd8bbb6e46c2ff4961e3815bed86aa2dcbaec765a21dd2e2730ed7ea8c3818d3440f677f6d32f6aff0708a581535e30dbe14d96bb39d1f03b02fad817f525ce742bffdeb0d76406659c7c2982d2e0c5b6e13f2634beb34c8b16780789bd1cf27d47a16c4bbddeb4d9a92251da983c29f934b206dd078fad13b53c6714e875ef104c033d194a2c73a90fa5563e60f5d7b470843e1863905ce97aa6510eb7e2e2480e43dc84f1863f7025b29c7147d3481fae46f2f38965cb7a5228168ceadbda176650581740ac1d8922af03641ce68442a9722c6c4929aafaa5397a2f854dac5804f75f9b0fbb12e75a8eeeeda0901cc9ff5fdd3f8e48c2ce41b020319b48a4284604475efb13627cf099d02cd02166ba8fce4b617fe2b839f95b964ecdfb34da0187f27fdaa902099e63f61567646bbc43b0180dcaf179f5cb14844773274568ff4cd3c0eb4fdcb05fe2b2fcc85346c07c80b0e647edad69018fd18b763cbd02b0a1ac42ff5d566b57a45a3ff74f545cc31d7d0e2ac7671284b8e7d2edc5cdabe9a85d37f8dc1de3c7cc6b7b7f61980d8b53d340961fd13bb5ce49aad388b68e55379aa0cf1d2ac928d4f8ddf87168485d96278d6198da35c6c3fe57e738a344bcb4103b13c2d495ffec8799d2836e96f2bcddb620ce038630863dc947ac7aeb2e1a722b186ce732a977efc5ff29d4594c598302c5e90407f79a0a35343198cd78a1aac7e3c44ed29b4d3b4409ba7eb362c74873abc66c02d899f50edf297db83e948ba59d622d9adafb720f95a8c03e5d46ab63ca50c55fadb97c6680d5a5295080934f62b04de71e87d101f0c8810da980b864304739e231076e161fc9bdcdd7bea6c0e75e9371bd017a729c1d675c65eeff58c3e34498c525a536a2ef849adb75c3c1fb47aaf78e6dc9226d0c055ad617e3df39906a2cf311aff31f53dd5581bcd46d6512dce657ab4069eee6a8a78332b3e14a6cbe8b7303ee7871086c7af35fdccaf85f3f97048168d584e0b96e3c8b82cf99b7f64c69e75f8c8f6f1298ccc7bfd4bc3745de35a3d518226b6cd163b08c6da50605f968db5f1b3a47086ddc382745d70151e3d86d293f5d4e2bf52fd800956624b5fa509467698384947a40670b06a687ad59e6989f2bc715fde213bcabd7835db91b05b0422bdf47f6fac3fab95ad94c2399566b4eae256a22dec7ea259dd536d5f6cb5024bbf715f6a2ff0d973ee2c0224d7998403aa44894273624a53d54a7e436ebd3ffc906cc3aa3893aff048315b624d5dfae7b09842fdaf9730020d242ad1c747e1dc8c86aaa94fa88e9fbd885140f49ac28a0e82b55cbbe7d47598c263a7d1fb6ecf866203beadbb5f5e687673c0da2051dd0fdb58d0862bfb3ccf96a65b81532d548fff8f7509a2f680f69cdc254d7eda038c6fef13e780cbdf7f0e1a1bf582d7e823e9a1d8415355daf16c230eab04958e22f855f73a8eecac6e8375768c989322d7cf6767fe852950509b24c972ff2fa35658c772bca29f63281f79539e3892a647986e0a5e2f8eeec9d029ce028a5259545d05b0934e4ba55a9cf2beef91cda3656e02c6789ceb4e20312cc4c6c40e2110cf509efe587f162ccffcf98b5a0c14de7451e1281c93eb855c8f36b26609f48c4672efee55c0a178a26dfcb0c7098a0ab67b16145688f754b1d34150ba097c091eaf5948546dba0c000fd665a9a75a77e0901dffe259a8d757c09a6ad845e6f4a5ba2bae26a44a6d89aebf2fbfa87146775b30e5c14d2e3eff2e0706ec7547c2473e8ef2a92410b34a10e3ca066975e2b477390649a9a5c2a2a64d12cce9f452677fc0d7954a6cbc398aea70fc9ec897b56ffe91a12a02d081560931eb6c7e5ecba5b2e90ac1d3ec8efd99527fe1b6520d22c41a634779ece3c9f3e84261b2976130fe9a35bd135edbe8b33bc15157352c7936b26e5ee70f70f6ad99cab1bf1fe930229a39e91df2246b7151f8aae2b1cf89ec79e2f35d8923d1e750fea4fa9779787a18a6cb1bd95892afc4d6ebe5db8ce51f156e17a6e6033dcb2f776eaa9cb8718eac8597cc359db6f57650bfdd15fc8b04f01391cbb56de0c70b77c6a32fd6de4d847f108b9cc1d4e345f7cf085643b5a8a35c7742105c66490d0ac950ab46cb081dbadd7c0309712df1a3e9856fbd65aa8bcd2cdbcddcbceaff2ae379e478ccd986eb537693583e54ea4852490282a0846bf63a04c09783a8c540f0e92b85f3621b735fa69d2990da43e20475cc91b007b1c483c37758791378527954c8666b1e161e052fb321e6591680742e62db17785003171fe28459d427b0ffb8f98b5026d5cf075454c2cf6eab18774a78b64f247907de1383e31eafc28d6a0a07d1464e02921e45106d22893e8a7f8613548329b632cdee9703d1145a4291c0284f097a42b95d4ac8c1bba8df283fc8e2d72a2e72ae1e2f36909993d210b34245e866fbd2c699e2e1fae2181ebbb8c51c1de6f1ea5e0107ec6eedc3c458ecece12fccc4b2c5709f02de4764c536acbc9debd24162ba36b53e98e6d7a7fb9bf4e64ff28ae1d366bc0fb702fb4b3dfed0cd925cda4f1282616fed98bf57d9a8be8843ba3800e05a9e84427c6cc6962a613d0853304d78a29cf3f31f89c0f37a97c2c91bdab19b0f49529a9c90de98e7fc6263eae5362275bb3c01e638c603803f89ab48e2d8c1192335fa71877c85a6b6040761671b3fcba54fb9515b1ed7133121e212234e42fef270687fa99d5a7e4b34b1411ba279da6d84503a08a0f470b878442d12970252fe655b5c3688cf4fce3e996ffa5df96770ae1344e62d858302b0959664e7454a287178663d3c467c25b36e5e1498c9a75081c9fba2b0928f115e96e5bdd8f7a41ee0fb19405fba9d425f04f32831718365bea5a0f6f75d1c508423b1ff92b820be8c5a3dc78bf3d9d2bef10cd536396d36b8c640c1ed11e6504fbe4d398de7e9d20789c5cc9fd343c005b2a4de8246509d7da73a5fcb46013ed5ba1688551c3536e92e9aa917b0b9466cf4be998f39973cc01ec048f88164858129c840dacb9b78aca5435e2a6552dd9ef04d256089b0204fddc01b6256c1770708a2e17a74148a1334bbbaa89be7aa6d417640129254388a3f82f9012c4b879bfdb08063178f84cff52ac0224fb134906ad10fa759a37dbdc5f2bf05551083904a3e7b340e55711de35cec7e6a206f9e3ea3397e4195d6267f59edcfd38315f80909385d3807d8e755a6cbd0a9c9e9dbb284d0194cd7f36c971dd178c9b5a26ef9877ecf2de40ef6e8ad5e8a52e7254d1ef98b5d5bce7ed4b483a3d07b595ea50ca3f2405e83a4a08be07f2a5b7c5ec78519292d706f9ad7dc053aadd40858a3458686fd2535c40344f37965356b47708052ca95c60c5dfbb9cd4790d3e656780d05c7fad6555bd3586134cca3e06421fa408545a4c9329ebddffe6ed73c3dc5c22debb1e249f3297ccc32367b4f12daeef2ccc2ebe6b470e03d37e06577bbc813e6d80bfd7254176560ed94eda0adfc07c8220354b8c9c9ca8853b3d156db4446349b7d9353d74aea7ce86c48806e14a8d155e40193e3db94d0a75debc790909d66fd2ce5278f415eb53b55385fb668bad03577e697005de1f96c3340eea66ffa67f4e2f78c04124c1e2c9e783aafa6bd34adad38c22b9311f140c7d9c1c254a2070dc2386623562ee9809042a8bfb280372cc234da1f853c58c30d0c109ca1edd1a0c3378147124b86757c292696e53e0da6aeddd243e31290a4a0f7eefb6fe1cdb58739b3c7a1eeeaddf4ccf5b76553cc75d98ff4e9bda7affc2adb60cbca5e55c809ef134d69da8a3ac3326743cece5bad79290dc71f0e6f786409770bfc8924184a54ca10fe3ef2c10ecea2e5a7dd37f8811db8fa4fae390f62f862c890dbc5032822fa2d417f01ae2ccf1154179b85ad7459d77f9e809a8573afba270be1d76174a18ca22538f30517f147c3663da3df696fc117fb52a1de621c801ddbb8f39f59ea4a69a120556deec7a9d6e5a205f53958d0aeddde56e2d76795d5add7b5a4cc158baeccd00ebea7e8deb6b77792a2071d8e17cf28868b22caa71bcfe436f9880ea1299ed8c0ad6ffe1bfa433de7f6a2d5d45cace37411683f9dbe537dcfa97f5ed562a7d749b0c3c7ca693b93bc8b625edb4cc51a214da1c2f5486d8ec8a1de1740609f88b431435143a5de81333a782e31fc85c8a1deb7d92248617c2197db9d1617cc3eeff75b2cefa5e72b5f4bf4ccf8fb2412e22111aac35d7c5c02cd8fc1783cc55f4e91dc68a2eb285713d8455aeb89e9088cdb54fa390596ffd80d676d91b4fa93ea1d69e22d71e0bc9920b75c8b7d5bc700a379dfdcf5fad3bfcfaa3747fc02dfd1bb2dfb53a63451a8a2bf4cee1b79f07b5d4bb737b8388842fa2db29111bfdd542e8dc74a4ea4eb6895d0fc8cc5ae55b4107fc318b3d4f26a85221761e19aa51e438d04743c8aff0a9c80b7a612e58432f95228ae6ac486922a0f3f90d4d5229ee197f879c39aab4a350b80bed7ce6ed09ed7e799ec0ba16d13a06baebf5d0357c8e0b1a026ea37ab1c871beef71a3120c0c50ff8a65a15e1f89d76061d83bdd8303a71d9fba39662db7ba4ac04d525f631594398a797adc77e70fd091ac002b98f10b8fd27b38b887a0ad66c25228df462e298c9f38d0964a2c49a17f3f96615214a0e59453609fd0df8bc940e9eec7a9e1eed4dd372cb9160b34fe5b1c7308d4e9cb042762d8f4ed5c5c9d6deac72e036a9c64993d22b9ea35e15f3792d55205511183d11a3cce9d736279c4043da74e3ffa81b5a2d34d294198d1468553074d47a1f00abab4035c5766d74f5722d9b91f94b7b6385c339cf8f8fa3b6d5fc382da11d835e9f20cec7f84be66935f0000"
        }
    )

    for txin in txins:
        tx = txs[txin.prev_hash]
        result = unblind(
            client, txo=tx.vout[txin.prev_index], wit=tx.wit.vtxoutwit[txin.prev_index]
        )
        txin.confidential = proto.TxConfidentialAsset(
            asset=LBTC_ASSET,
            amount_blind=bytes(result.blinding_factor.data),
            asset_blind=bytes(result.asset_blinding_factor.data),
        )

    txouts = [
        proto.TxOutputType(
            address=get_confidential_address(client, "44'/1'/0'/0/1"),
            amount=2995000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=b"\x11" * 32,
                asset_blind=b"\x22" * 32,
                nonce_privkey=b"\xAA" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address=get_confidential_address(client, "44'/1'/0'/0/2"),
            amount=6995000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=bytes.fromhex(
                    "44979dc8ed9126da3f7ce8bb45f53e662a53f75e074618153e2b350fd2dec0ce"
                ),
                asset_blind=b"\x44" * 32,
                nonce_privkey=b"\xBB" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address="",
            amount=10000,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        ),  # fee
    ]

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
                proto.TxRequest(
                    request_type=proto.RequestType.TXOUTPUT,
                    details=proto.TxRequestDetailsType(request_index=2),
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
                    request_type=proto.RequestType.TXOUTPUT,
                    details=proto.TxRequestDetailsType(request_index=2),
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
            txins,
            txouts,
            details=proto.SignTx(version=2, lock_time=0),
            prev_txes=None,
        )

    print(serialized_tx.hex(), file=sys.stderr)
    assert (
        serialized_tx.hex()
        == "02000000010178605716099fda550f37be2180f8b93d17b3da2933152acc645f692969e3841500000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac652083b372d4bd469416fad7d72cbde362923809905fb4303a39125b517496a3de9de026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e81085409b8d2915bfa86aae9b195e278032e69b579c0764a2d6f58ac0bbaf1fa543a3dc60268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000271000000000000000000247304402206456952ad36556e88d6a4766a99ec0859709d8b58294c1a98c2936c12e9576230220644f632edb324a561f0578115992a2466df9fd4ecb62b5533b4866bf2d6be1f30121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00002073af2919faec87f01ed3c5b201fb23eff22e51c85fa8aacd2ba1bb08fedd44650020041eabe902b0faff49277ae6f0a3232ad1fa6bab9aab224ee59edce3bc7abae10000"
    )

    tx = generate_proofs(client=client, tx=serialized_tx, txins=txins, txouts=txouts)
    assert (
        tx.serialize().hex()
        == "02000000010178605716099fda550f37be2180f8b93d17b3da2933152acc645f692969e3841500000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac652083b372d4bd469416fad7d72cbde362923809905fb4303a39125b517496a3de9de026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e81085409b8d2915bfa86aae9b195e278032e69b579c0764a2d6f58ac0bbaf1fa543a3dc60268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000271000000000000000000247304402206456952ad36556e88d6a4766a99ec0859709d8b58294c1a98c2936c12e9576230220644f632edb324a561f0578115992a2466df9fd4ecb62b5533b4866bf2d6be1f30121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00430100016561c226356a4c21008ca00dd9ab8691c223702a514b6b93842708478f95f51549954fa74abbd2265e6cc687ed4d1d87aca8026a11658f4def3e2aec7a4f6631fd0c0a601f00000000000000017d288c455c863d9e65b8e4c342c391c7db9ae8c2a83f80aa20a38baf99de1c291a6bdb4a52858c78b63c364df1a171173618018a03ebed94fa8eb65207288cf2c5d5aa5d042e23324a3ed91859f634b726b98e8d4d1921ad0f71c22c5d8caf9bdc883d11b3d649b50f39af0860ca2ce0f458f85c8cc9a641e518e861f7ee5a9b23284808e5db99c447c4a4dd205021a87f8401b90eae2d758dec2e39eb2b3df66cdc6ec645b36d3b207b437c5416ebe5793024a65a287f449f39da92e94c481e398bcb9c6ac60dfecca40c34386585134e92ac87e739cfbdca988bc2e6ff295fff176e4578c65e4ae2a9e83cae0429d04f61b2a577d15444422df24788505029b959cb1c6d51102926358127215db3cf7d97f8bd866ae3acdd168e8356c94f6176830ffbd5ac58310e2670b90c9d3ecd1a67ac67ea3fb001426bf421d02acea87967ab20173f9e8ab34cb5904b6ddf4666fc39be17fbfa34930719a61ea1ddf6555daa3c9529542a45f9b53c155e69c87bd2ba831844b09d04bb91de29b0e381fc3ce9413064dfceeb4ca3bbfce35edb80d51b0a45ecc59da29a0b85055a8d50c1f6094b1d44d5ceb92745ea3b3efb5543a4e013f3a77434e0b17c1070fa1e7e564e4991e84e4dd50b2b696cb54993532689ac2334bc3d0d31ae424aa2ce49741a38c1cde36c8ae2b8ca2bfd39f39c30d9700ab958252988f9d68489ebf738574f1ec4b98886810c4c05703d278ea7d1db14077e31df8d720e61720bc23c4efb2ae25cf4d394f23e5a619668ca191458417f9f67f3b12c21bc5a4644e909d1f37e8b4b0146a6d57a71d6358edb0d0b6395956b0cf7ab94ac43d7e4fd6360bbf3d88c08c206f1dbed95c3e3b8a0fb4815f1000a75fcbbb17df30b1964c32d772a9f9ffe4fcbd7b5aa87d428bfb8b3c1a1a9b501504c2aa36563c7209892a64417bb84d9ed99902cacf7c0a4b4fce6574a7f5f83e6ab0cef0d2f4bd4453a374ed31c38684510f7ad075d199d72b4a7446fdc90d4532abe665dde2496f4b8e97d15cab6580cbb0748d9ec52d0ffcd506368e0273c78bc762bebf63f138f98c868ec6b691054dd0ccfc515e1194ed46f54901bf89c24c4b6acb2b6322a9959f89f797467233b5c8bca35a4ecacebdf507976fcd0d74b8cdce83dac6339f8b84472a6479fb187829f31a30885fd0b5825bd420b6e436d0942b5856da7bf9f120197327123859f8308cf0567eb4427f0d4471848fe985c6308c9a0b59fa2023ede00df7e46c5605a082c4798070f30cec4e1fa8ae47f5f045bae74093d0f736c45fe66629e50308fead86e52b90e1de93990e039c48438b987f3083cbe1e1e774a8d28dc538ac685b2bc329f87fb437d28014be11d5b721f7a61befa7003956ffb1a01eb9b01e61ecae77064abb75fd8e9ffc64130ddbe6b531775b06bff7eec0518b7d9b84c7130d63211b9219f12829f4a11649325583b4dc45a78a9760ac94dd50052657b6649489586bc34446d13e7a9ffc8ad25ae3029fcb57704f25273817754d00019cb14fc4d658df2bbabe9cf59a74974b967846386141fa4dcb77607854348084326afb84072353ad66367641916ec274b3fe8fab21f9431b2c885a1b52fef56de4e86d538c396e7ad9928818434da365f74973e7e640f5c291cfc452eaba3db2be4163df4db373398e17a9203c861e1cf421f0724cc6265432b45e370945c67771d94b2716cc751c8a4f868542fafd91d429ed6d149e9f1cb0bfd437d07e52802a480bdb91bfb8ab81fb3fd54523b7a0a5b845509722b828fe198d7743994956f1f17fafb06253afd87f44be9fbecb9c2df1b3a53a51b89eb334ec8bf5f140895358dbd6fc92475eaeef577bb47ed0f82ddbd320cf3574f9f41402980f632ce6a427ee77c69b59ae345d34d091a47fe9e8f521cc210ee20edb124aad650b1cb5699618a8239f61ebff227ae03971054b2d1a97d4297f6d26ff2557fab6c7c205c69e1d3da2bf69f8cf3600f73a52c582f7757e25f9ed503dc4ee5ce45927d5f852677610f398d3c9d94829e3531aa59265f54a6926ff747e14a3651af27ac08bd3f6e71361ae17433ea49a8050f4e3ecfd701b61768de48249822c4f99c93ce913d7f7a78bef1453e6ef0579a9b5613c7571660966bafef2452d11ac409a9fdc64141cb8faeef4cf99d502f832d1a8202037c1c0a2094b51d1eac098802086f259f0261cbab07d692b88e4c4b9718c764c325ef4a0e604fff72f2f2878597cc78bb8ebae0759961f78c0a09cd270fcd51b2445d971b22e8c58c8c6b2970171c9bd0e8b514135fd9179f5d96e54578267d6a4c444ef7b2422090dd442c530b11bc0a6cdfc0435c1f32a16d7dde6332323a12559c0d2501f6bfe8d8f00ae141f8e490ca9ca165616623ff5b76847f8bf189faff85c1a7d54175970c09cc379b2cfbe4fe2632bd920d49d10ee6aa2559131a87915f8551affdb877ad7e8ffaabe4c422d7ed20b80e5e75bd807fb56cc40becfed149ed6d2e507811c24bf350a42dc9e6864163c9c3b99fc51739579b9b09bdff2a92b04263ff1521717565d1f6a134cd66b300ce89ebbdab96df38d8fed3e9fbe345fee891d3cfc82fd8f50871dfa4ce2ad069d1819feef1a4e00ca0adb7ba5923eccfa2879ef1754509fda6db8d1ca244a2e631c72f647e50edc069929cd1acbb3be3d5e5a752836dab795e48a9cbb5472394bfe32d42cc387cd780f4cf05051bca136b53be3f3a9c4637ee574d607195b5eff3d232c186f80d486fcb01b7d9d55218ad43ddcb15e4f0944ecf42e1a87dc645d9f6fead7588ccc6afa64a6d3d90cbe4ae122cb6b773fe6441fff4041c24f894a94bc9f39ed851ef55ab8ebdf440da87f3ca7a796288b71c93267b78a1ddb9413b94b496a878534724bdbf3ac642e63f607c7ff83797b7386cb1adb88632f85f0e8d5caa0f93e1a9dc0d733e09c6774c22d887e5bba69e9133b28652a7db73377f5ea27d409d5bed9a0cb844b9cdd8cd703c32bb9f04a24658cdb73d8726a03ed82c27c2e2fe98eda22b5ea828a5f3f53149892d3208564fcc8171faf59cf4ed071de10d84b126dba9e3ba68558f88a038079bd9d8ec79bc4391e6d328208ac86530bd970875759cc847def42104dcc6787dd89e1dd1d0564bddadef7679bf77afee50991713ecba514764a5663626f5935fa9fc57e71a2d8c0a7b5994ff22b4d60c34f8b40e9e1a3765f829804a3fc4f003876da5624885fbc98b5add54ee6ff70b9a9ef284af4498c49e7ca040a9e0c3fc7ad0daa5a092785ca5da3de40d7a689c676ed2122127e5d15313d5b6dd66a12edf56c0347fbab26471b3113149abd03c329f087d78a328e337bc7bc796bc98ea764e0f7d9f468554ad09bc8be415fe177d3cc7c53d1454c2ce8498998450fe528a0b2692cb7f677aa12639e4b77c79bff2f31b3dbda8ef74f02e514613c84ca6847d93cab83b1b7ae7b3c6871c152c71afdd0fad2544f443f5cfecc0e4c4ecdbee4094023fe19395ac3c44bb5ed4e5c190542036d533e2ce9b712c985448ef8807ae78928440bbdcaa4876f106abbb3befb5ba58dbaf086e892832b345e670ddf6fa6d5168c8b3215e430100015462b4ad56d7475b7d0b0e34795ecd4a2ca35ee7c766db384dfcb059e74779fd453d184e8f7a35631a27d399db4916894aa61326a6faf8efca0e159998657a5cfd0c0a601f0000000000000001c02984316a1be3fa0f73f94cb86894c525b521316cedb17246c4a68524af74f70927326f2ef2fba9965fb9330e6d9a406b2c9015702cfbe890d92283bbf83ca789cceff734c8d0e28be3ed50f462b5be2cd622fa5da620c77634c931521772c2720c36dbc03ebe7dea94294ebad9727b3a9a4a3ff470739b28a57a5a92a9e1d0ffa2a97898178c5fbb41a780d2a4f7e2a78890f62efb55e85dd401414022034161c10eb5fab58019b14d2e464f3b1d6300618036a1a4cb16c666f2342c004e181688c9adc419c4996840daed98ea40beb7eb0941b6a05d80b563dbba4fc284901f6a824c5078fa4b8fb947e76dc7052acac948944d72ee8767bf2511a02edaba5ddc5d057766c4a1d9dc6db274f973161b3e62f523cdcbf668916ff96ec75142a48c82a48ba5f6dc18535c9f46be2bdac1a9f6b7cec577772b88abcd0949cc6a83351001f6a2d1b34487ed79492779a5559bbabecd0c85e451400b895d6a477a5a13d3288dc7824c791d79ffa862fd3adeeb3d5261deefc513b58dd8af0e1bee96da7caf1774b3527038b0a4619a96f8865853957a48f1ece557b8f60125c526574e36e324f6e31fe7b57133ecea298003e3659c0fdfacd5a6dc8d0b461fe458daef6d40a44bedd9d0b1db75580c96dae2f323a60e1ca44af7560736253ebfd59667ec8977d7d56372f24301dc364bfe51e4b7cd8ed33628def79bf09f08c8568bed73e1fdb4e40a1281157ab084cfa7777f45944eeb242749bb8fe2e8a186a12b1b28c223bc01e9138fe0814748b757913a7ed446c7af7c8ac7c5ee1ec86d739a8b4226b25ced682685a40e5950a8da1212c3bc795326163c1687e4a38173fe900846d66bfa58d9fdf961f5df70b854d5e5307ae535b83d616b06ef874292b5ed3a5cae182d15cd6d3bd42bd281fb49f5f3f3f98b18c9d23e1e852784b1ec152982442cf3d0acd70d3eac33b34fb4fb174de1eb5ecaa2e9d4741bfe4f357ef5b48e4991a24863a604b17a28d57e225adc7c86aa86f5512c08b594349459416e97828971b1d8f0531c789e07b8fd21dec537aef50356407c6434fb60608f0c8b200a02cd7dac8dadbde4d1c023a0ffe4c215fbd02049edc273c74c06747557608a5a9ca9953fd4dbff3dc76e93e03dfe562431a8f7e40fc3977044ba76b13e1b6e994d32dcd7ac84e20030402f3db570db8b8e604458e7c1d9c739e0b44f33e5c93fa32fce296105b2074ba68bd5a4a53d4437e52ee3dbeddb36ea94d200f76c15e822601b959632bad778a58675c3a706a8785e649fe79addb8112d7aa1e31878bdfc4e13419ba85a29c8c3f63b73f9f86f805ed6d8c0a64d6b28b0a988a710d4edcdf2c184a448f147158cc8363b1c64f2bbe7154029dfffbefb7fe3f464a9b68acc461fbabedf3f6b3f903127930c9c5f8246fabc1719d5fb2354057d20cea0a541cd09b169dc04af8ac576c31b378bb522a6b35cf6e2bca2fd967b729722246696b5a2804c43a0fd172847e44a4d3486b7246ff7556430d80c3a7eae5acd0b84939c91c72e5c983badceea171048a91dfbe49abdcd6b4ab5de74e1d2f0e9ddd9169d631f250d4778b3a6f8df7742eca0f7e975bd6714b6d8055bf4cba88f55384155382485b4acb1e1a8aa57e2856c7027840a1ff951123bd86acdb3f53a5cd89d7cd1d5e9f0f80d1688ecfbd76517ea4e992e77fa3d7e88f7fdffa4b2046ea16271284337a8314829ae92266c007f8ce8fb0c6b6d8db649b3169d18c357e9b88de61bb796796ec65c5f6903386a77be99481aeabf9d0b328422d51a99926dbe8111b0be5c9c04f6dd6d99d8db42eb58d003e335e23ae1be8cb9f492c788892d9165b55e8f07bdc88c3e194d00ddc38d110fc199ff34d31902d9f309704b1a9e42296736b29cd8631865518eca963cfe9f7be047b8be5ae8c8e8d56a978a9b17c8a0a80f4aaa90728a53d4e7ee9b7d1b1464973b60938b6801fa11a7b855170fb587a16c979bdc2455d0328ab4194f7f6fef7e31dad6ae3814b08b32b02703fc7acbd49464ddb31cb1393c1b6cef700ae2303076e1b44c0a1403d7125a1a6176950cedd724e84544084790007502c94997cfb5f28f6e6630f0c66d54f8dce4a6f5b89f68316c6d999f78c6083c866bb6301f35c9a4f8a13dba0339e95ef8fd4edcd3f52bccc3207e0dfb8838b2c1298c6784de70c3c5ac5567de821e7123154c18762fc3f6d0c4ccb6e1beaab8238e8a6e3754d19303e532f2a4754813fec6c2408cb7966867f3771b4be412631f618327eee73dbfdd89fa07a8b9119c0cbfb43f4744fd9bb57cd393b4beee3cc37a8347422b0a176e151aee7edc053e70462fcc29764da98a905b968b1e2ce0e7aa3fcebc2dca5f0c65e00af418ba4430832ab5d0d2fd071dc1ead1c07963de77c2feaee83fc830717c14ca4389652fde375a22bce0abaa1d91fcfdfa063bf089a5ecf7a1d2028c38060d5f78540a952eda8295436ee22d1206e616097797781b99a46d0e611df16b0b9fb6337cb208eb54d9318679c73306d1d1c08b98f48798deee38df1339a57287ddccb324ea606d11b99d748383dac425643103c0253e48530ebffcf851ec1c04972d6387d474d4145030fc30e8d32f58ba4c98eed1702b03eba71d002d73cff85c381224446baa13d487847cef97a7be3ac39c1f740374f8558273659ec8f06c26663c9a84df53f592010575b69eb696b16d4e8af34a018d8d8aafbead6924077210ae0d15f1cf9ce8a3492f09f2f25ab45ae45a9325687183e4f336f9a81672b5b796c15f9d751cb77747a54af3628aa4966640f307ca6823745c6d19e91438ddc1aab6548020be5fc643fac93b0243a085d2fa69fb8041dad10abbb22c06600c238f15962bd333450527e99ddd055931365e0c5c828574a102e076f729565635a4ac03b8da92a164e9b166aba81dfb6983bb14759bd59ad31a800a41119fc63a5bd19677f8759c9958731bf668815d0fc8f635d68d327dfc2bf4ca2f915658a2f5a6efa36151754f4b2752fb37894e29d49e9096ad7d7d406afd3821ec2a7db40a81d476a836ba1ce3b4369eb07cfdc2ef9376a8b35290810112101ac0171fce9f5ec353c00acce6956d351fd583a28b9156a0d83c5a2bf5b8da59229fd2831c8599a04646be34c39370ba54c9d1ef990b38fd3be08f7b385865bdf8d37d116d2cad5f90cb05759e0a7a93dcdafda7606c9677e34420c29eabbf9a9f7ba8c74202818c8580db5216ece31a198bf9a72e186b4877d0c3fd1da42378df68f38abae693e0c8ce76fe4656f761b63096c7c0df29b90a300cce139d246a3ec124ff36d67bb5e5daf9a8afeacd5e0a77fe61e101b001bf6c5951cfc40c4a8bcf8ec32be90ec685141c415f62b6edb7f0bcd5822959b9858ef871f01c3d151c23bb4a0b20df4c5ec868562c558220bded438de75162822bcee54483848de64ae6065dbf06187092f55b8a955eb4f72713ba136cc7286b2947f6f1d546bdcc015e89145e9645f8a960b472455dfacd0a5966f76f03ee754f6a38262dd3a1d3ba65f2e37bd678797c7ea90b7fb42ad20c9990b29ee0c110ee40b446b07af03b89d04ad73e8ec855ba713da8300000"
    )


def generate_proofs(client, tx, txins, txouts) -> CElementsTransaction:
    tx = CElementsTransaction.deserialize(tx).to_mutable()
    with ChainParams("elements"):
        NO_BLIND = b"\x00" * 32
        input_assets = [CAsset(i.confidential.asset) for i in txins]
        input_asset_blinds = [
            Uint256(i.confidential.asset_blind or NO_BLIND) for i in txins
        ]
        input_generators = [
            blinded_generator(asset=asset, blind=asset_blind)
            for asset, asset_blind in zip(input_assets, input_asset_blinds)
        ]
        for vout, out, wit in zip(tx.vout, txouts, tx.wit.vtxoutwit):
            if not wit.rangeproof:
                continue

            amount = out.amount
            amount_blind = Uint256(out.confidential.amount_blind)
            confValue = vout.nValue

            asset = CAsset(out.confidential.asset)
            asset_blind = Uint256(out.confidential.asset_blind)
            confAsset = vout.nAsset

            # HACK: the device returns the ECDH nonce via the txo rangeproof witness (to be replaced by the actual rangeproof).
            nonce = wit.rangeproof
            assert len(nonce) == 32
            scriptPubKey = vout.scriptPubKey

            wit.rangeproof = generate_rangeproof(
                in_blinds=[amount_blind],
                nonce=Uint256(nonce),
                amount=amount,
                scriptPubKey=scriptPubKey,
                commit=confValue,
                gen=confAsset,
                asset=asset,
                in_assetblinds=[asset_blind],
            )

            assert unblind(client, vout, wit) == UnblindingSuccess(
                amount=amount,
                asset=asset,
                blinding_factor=amount_blind,
                asset_blinding_factor=asset_blind,
            )

            output_generator = blinded_generator(asset=asset, blind=asset_blind)
            wit.surjectionproof = generate_surjectionproof(
                surjectionTargets=input_assets,
                targetAssetGenerators=input_generators,
                targetAssetBlinders=input_asset_blinds,
                assetblinds=[asset_blind],
                gen=output_generator,
                asset=asset,
            )

    return tx.to_immutable()


# $ e1-cli getrawtransaction 7ac908356bd379aaec2008fefee2ebf56902262c309824473dddfef641ed3521 1
# {
#   "txid": "7ac908356bd379aaec2008fefee2ebf56902262c309824473dddfef641ed3521",
#   "hash": "c64463db7bc3cf4f37aac90ad1282507a957db6e00224477f8cfe1218d3713da",
#   "wtxid": "c64463db7bc3cf4f37aac90ad1282507a957db6e00224477f8cfe1218d3713da",
#   "withash": "f4c405fdea5d9a3b4a8688aaab38c11f1c6bddd8d8a9b57f9065349a2a03b80a",
#   "version": 2,
#   "size": 5763,
#   "vsize": 1715,
#   "weight": 6858,
#   "locktime": 0,
#   "vin": [
#     {
#       "txid": "1584e36929695f64cc2a153329dab3173db9f88021be370f55da9f0916576078",
#       "vout": 0,
#       "scriptSig": {
#         "asm": "00140099a7ecbd938ed1839f5f6bf6d50933c6db9d5c",
#         "hex": "1600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5c"
#       },
#       "is_pegin": false,
#       "sequence": 4294967295,
#       "txinwitness": [
#         "304402206456952ad36556e88d6a4766a99ec0859709d8b58294c1a98c2936c12e9576230220644f632edb324a561f0578115992a2466df9fd4ecb62b5533b4866bf2d6be1f301",
#         "033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "083b372d4bd469416fad7d72cbde362923809905fb4303a39125b517496a3de9de",
#       "assetcommitment": "0bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac652",
#       "commitmentnonce": "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3",
#       "commitmentnonce_fully_valid": true,
#       "n": 0,
#       "scriptPubKey": {
#         "asm": "OP_HASH160 34fbecbc9786f628943d2abf87d66957bb6b35d0 OP_EQUAL",
#         "hex": "a91434fbecbc9786f628943d2abf87d66957bb6b35d087",
#         "reqSigs": 1,
#         "type": "scripthash",
#         "addresses": [
#           "XGBPnAAFRbdgxtofjVGjNqBw2csVueMW7g"
#         ]
#       }
#     },
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "09b8d2915bfa86aae9b195e278032e69b579c0764a2d6f58ac0bbaf1fa543a3dc6",
#       "assetcommitment": "0bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854",
#       "commitmentnonce": "0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5",
#       "commitmentnonce_fully_valid": true,
#       "n": 1,
#       "scriptPubKey": {
#         "asm": "OP_HASH160 0de6434adf2f3912732cdc20db3e2145a00e61e9 OP_EQUAL",
#         "hex": "a9140de6434adf2f3912732cdc20db3e2145a00e61e987",
#         "reqSigs": 1,
#         "type": "scripthash",
#         "addresses": [
#           "XCcjUakcNNMP7L3Z6yYprrPxSbhW7RYVN4"
#         ]
#       }
#     },
#     {
#       "value": 0.00010000,
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
#   "hex": "02000000010178605716099fda550f37be2180f8b93d17b3da2933152acc645f692969e3841500000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac652083b372d4bd469416fad7d72cbde362923809905fb4303a39125b517496a3de9de026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e81085409b8d2915bfa86aae9b195e278032e69b579c0764a2d6f58ac0bbaf1fa543a3dc60268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000271000000000000000000247304402206456952ad36556e88d6a4766a99ec0859709d8b58294c1a98c2936c12e9576230220644f632edb324a561f0578115992a2466df9fd4ecb62b5533b4866bf2d6be1f30121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00430100016561c226356a4c21008ca00dd9ab8691c223702a514b6b93842708478f95f51549954fa74abbd2265e6cc687ed4d1d87aca8026a11658f4def3e2aec7a4f6631fd0c0a601f00000000000000017d288c455c863d9e65b8e4c342c391c7db9ae8c2a83f80aa20a38baf99de1c291a6bdb4a52858c78b63c364df1a171173618018a03ebed94fa8eb65207288cf2c5d5aa5d042e23324a3ed91859f634b726b98e8d4d1921ad0f71c22c5d8caf9bdc883d11b3d649b50f39af0860ca2ce0f458f85c8cc9a641e518e861f7ee5a9b23284808e5db99c447c4a4dd205021a87f8401b90eae2d758dec2e39eb2b3df66cdc6ec645b36d3b207b437c5416ebe5793024a65a287f449f39da92e94c481e398bcb9c6ac60dfecca40c34386585134e92ac87e739cfbdca988bc2e6ff295fff176e4578c65e4ae2a9e83cae0429d04f61b2a577d15444422df24788505029b959cb1c6d51102926358127215db3cf7d97f8bd866ae3acdd168e8356c94f6176830ffbd5ac58310e2670b90c9d3ecd1a67ac67ea3fb001426bf421d02acea87967ab20173f9e8ab34cb5904b6ddf4666fc39be17fbfa34930719a61ea1ddf6555daa3c9529542a45f9b53c155e69c87bd2ba831844b09d04bb91de29b0e381fc3ce9413064dfceeb4ca3bbfce35edb80d51b0a45ecc59da29a0b85055a8d50c1f6094b1d44d5ceb92745ea3b3efb5543a4e013f3a77434e0b17c1070fa1e7e564e4991e84e4dd50b2b696cb54993532689ac2334bc3d0d31ae424aa2ce49741a38c1cde36c8ae2b8ca2bfd39f39c30d9700ab958252988f9d68489ebf738574f1ec4b98886810c4c05703d278ea7d1db14077e31df8d720e61720bc23c4efb2ae25cf4d394f23e5a619668ca191458417f9f67f3b12c21bc5a4644e909d1f37e8b4b0146a6d57a71d6358edb0d0b6395956b0cf7ab94ac43d7e4fd6360bbf3d88c08c206f1dbed95c3e3b8a0fb4815f1000a75fcbbb17df30b1964c32d772a9f9ffe4fcbd7b5aa87d428bfb8b3c1a1a9b501504c2aa36563c7209892a64417bb84d9ed99902cacf7c0a4b4fce6574a7f5f83e6ab0cef0d2f4bd4453a374ed31c38684510f7ad075d199d72b4a7446fdc90d4532abe665dde2496f4b8e97d15cab6580cbb0748d9ec52d0ffcd506368e0273c78bc762bebf63f138f98c868ec6b691054dd0ccfc515e1194ed46f54901bf89c24c4b6acb2b6322a9959f89f797467233b5c8bca35a4ecacebdf507976fcd0d74b8cdce83dac6339f8b84472a6479fb187829f31a30885fd0b5825bd420b6e436d0942b5856da7bf9f120197327123859f8308cf0567eb4427f0d4471848fe985c6308c9a0b59fa2023ede00df7e46c5605a082c4798070f30cec4e1fa8ae47f5f045bae74093d0f736c45fe66629e50308fead86e52b90e1de93990e039c48438b987f3083cbe1e1e774a8d28dc538ac685b2bc329f87fb437d28014be11d5b721f7a61befa7003956ffb1a01eb9b01e61ecae77064abb75fd8e9ffc64130ddbe6b531775b06bff7eec0518b7d9b84c7130d63211b9219f12829f4a11649325583b4dc45a78a9760ac94dd50052657b6649489586bc34446d13e7a9ffc8ad25ae3029fcb57704f25273817754d00019cb14fc4d658df2bbabe9cf59a74974b967846386141fa4dcb77607854348084326afb84072353ad66367641916ec274b3fe8fab21f9431b2c885a1b52fef56de4e86d538c396e7ad9928818434da365f74973e7e640f5c291cfc452eaba3db2be4163df4db373398e17a9203c861e1cf421f0724cc6265432b45e370945c67771d94b2716cc751c8a4f868542fafd91d429ed6d149e9f1cb0bfd437d07e52802a480bdb91bfb8ab81fb3fd54523b7a0a5b845509722b828fe198d7743994956f1f17fafb06253afd87f44be9fbecb9c2df1b3a53a51b89eb334ec8bf5f140895358dbd6fc92475eaeef577bb47ed0f82ddbd320cf3574f9f41402980f632ce6a427ee77c69b59ae345d34d091a47fe9e8f521cc210ee20edb124aad650b1cb5699618a8239f61ebff227ae03971054b2d1a97d4297f6d26ff2557fab6c7c205c69e1d3da2bf69f8cf3600f73a52c582f7757e25f9ed503dc4ee5ce45927d5f852677610f398d3c9d94829e3531aa59265f54a6926ff747e14a3651af27ac08bd3f6e71361ae17433ea49a8050f4e3ecfd701b61768de48249822c4f99c93ce913d7f7a78bef1453e6ef0579a9b5613c7571660966bafef2452d11ac409a9fdc64141cb8faeef4cf99d502f832d1a8202037c1c0a2094b51d1eac098802086f259f0261cbab07d692b88e4c4b9718c764c325ef4a0e604fff72f2f2878597cc78bb8ebae0759961f78c0a09cd270fcd51b2445d971b22e8c58c8c6b2970171c9bd0e8b514135fd9179f5d96e54578267d6a4c444ef7b2422090dd442c530b11bc0a6cdfc0435c1f32a16d7dde6332323a12559c0d2501f6bfe8d8f00ae141f8e490ca9ca165616623ff5b76847f8bf189faff85c1a7d54175970c09cc379b2cfbe4fe2632bd920d49d10ee6aa2559131a87915f8551affdb877ad7e8ffaabe4c422d7ed20b80e5e75bd807fb56cc40becfed149ed6d2e507811c24bf350a42dc9e6864163c9c3b99fc51739579b9b09bdff2a92b04263ff1521717565d1f6a134cd66b300ce89ebbdab96df38d8fed3e9fbe345fee891d3cfc82fd8f50871dfa4ce2ad069d1819feef1a4e00ca0adb7ba5923eccfa2879ef1754509fda6db8d1ca244a2e631c72f647e50edc069929cd1acbb3be3d5e5a752836dab795e48a9cbb5472394bfe32d42cc387cd780f4cf05051bca136b53be3f3a9c4637ee574d607195b5eff3d232c186f80d486fcb01b7d9d55218ad43ddcb15e4f0944ecf42e1a87dc645d9f6fead7588ccc6afa64a6d3d90cbe4ae122cb6b773fe6441fff4041c24f894a94bc9f39ed851ef55ab8ebdf440da87f3ca7a796288b71c93267b78a1ddb9413b94b496a878534724bdbf3ac642e63f607c7ff83797b7386cb1adb88632f85f0e8d5caa0f93e1a9dc0d733e09c6774c22d887e5bba69e9133b28652a7db73377f5ea27d409d5bed9a0cb844b9cdd8cd703c32bb9f04a24658cdb73d8726a03ed82c27c2e2fe98eda22b5ea828a5f3f53149892d3208564fcc8171faf59cf4ed071de10d84b126dba9e3ba68558f88a038079bd9d8ec79bc4391e6d328208ac86530bd970875759cc847def42104dcc6787dd89e1dd1d0564bddadef7679bf77afee50991713ecba514764a5663626f5935fa9fc57e71a2d8c0a7b5994ff22b4d60c34f8b40e9e1a3765f829804a3fc4f003876da5624885fbc98b5add54ee6ff70b9a9ef284af4498c49e7ca040a9e0c3fc7ad0daa5a092785ca5da3de40d7a689c676ed2122127e5d15313d5b6dd66a12edf56c0347fbab26471b3113149abd03c329f087d78a328e337bc7bc796bc98ea764e0f7d9f468554ad09bc8be415fe177d3cc7c53d1454c2ce8498998450fe528a0b2692cb7f677aa12639e4b77c79bff2f31b3dbda8ef74f02e514613c84ca6847d93cab83b1b7ae7b3c6871c152c71afdd0fad2544f443f5cfecc0e4c4ecdbee4094023fe19395ac3c44bb5ed4e5c190542036d533e2ce9b712c985448ef8807ae78928440bbdcaa4876f106abbb3befb5ba58dbaf086e892832b345e670ddf6fa6d5168c8b3215e430100015462b4ad56d7475b7d0b0e34795ecd4a2ca35ee7c766db384dfcb059e74779fd453d184e8f7a35631a27d399db4916894aa61326a6faf8efca0e159998657a5cfd0c0a601f0000000000000001c02984316a1be3fa0f73f94cb86894c525b521316cedb17246c4a68524af74f70927326f2ef2fba9965fb9330e6d9a406b2c9015702cfbe890d92283bbf83ca789cceff734c8d0e28be3ed50f462b5be2cd622fa5da620c77634c931521772c2720c36dbc03ebe7dea94294ebad9727b3a9a4a3ff470739b28a57a5a92a9e1d0ffa2a97898178c5fbb41a780d2a4f7e2a78890f62efb55e85dd401414022034161c10eb5fab58019b14d2e464f3b1d6300618036a1a4cb16c666f2342c004e181688c9adc419c4996840daed98ea40beb7eb0941b6a05d80b563dbba4fc284901f6a824c5078fa4b8fb947e76dc7052acac948944d72ee8767bf2511a02edaba5ddc5d057766c4a1d9dc6db274f973161b3e62f523cdcbf668916ff96ec75142a48c82a48ba5f6dc18535c9f46be2bdac1a9f6b7cec577772b88abcd0949cc6a83351001f6a2d1b34487ed79492779a5559bbabecd0c85e451400b895d6a477a5a13d3288dc7824c791d79ffa862fd3adeeb3d5261deefc513b58dd8af0e1bee96da7caf1774b3527038b0a4619a96f8865853957a48f1ece557b8f60125c526574e36e324f6e31fe7b57133ecea298003e3659c0fdfacd5a6dc8d0b461fe458daef6d40a44bedd9d0b1db75580c96dae2f323a60e1ca44af7560736253ebfd59667ec8977d7d56372f24301dc364bfe51e4b7cd8ed33628def79bf09f08c8568bed73e1fdb4e40a1281157ab084cfa7777f45944eeb242749bb8fe2e8a186a12b1b28c223bc01e9138fe0814748b757913a7ed446c7af7c8ac7c5ee1ec86d739a8b4226b25ced682685a40e5950a8da1212c3bc795326163c1687e4a38173fe900846d66bfa58d9fdf961f5df70b854d5e5307ae535b83d616b06ef874292b5ed3a5cae182d15cd6d3bd42bd281fb49f5f3f3f98b18c9d23e1e852784b1ec152982442cf3d0acd70d3eac33b34fb4fb174de1eb5ecaa2e9d4741bfe4f357ef5b48e4991a24863a604b17a28d57e225adc7c86aa86f5512c08b594349459416e97828971b1d8f0531c789e07b8fd21dec537aef50356407c6434fb60608f0c8b200a02cd7dac8dadbde4d1c023a0ffe4c215fbd02049edc273c74c06747557608a5a9ca9953fd4dbff3dc76e93e03dfe562431a8f7e40fc3977044ba76b13e1b6e994d32dcd7ac84e20030402f3db570db8b8e604458e7c1d9c739e0b44f33e5c93fa32fce296105b2074ba68bd5a4a53d4437e52ee3dbeddb36ea94d200f76c15e822601b959632bad778a58675c3a706a8785e649fe79addb8112d7aa1e31878bdfc4e13419ba85a29c8c3f63b73f9f86f805ed6d8c0a64d6b28b0a988a710d4edcdf2c184a448f147158cc8363b1c64f2bbe7154029dfffbefb7fe3f464a9b68acc461fbabedf3f6b3f903127930c9c5f8246fabc1719d5fb2354057d20cea0a541cd09b169dc04af8ac576c31b378bb522a6b35cf6e2bca2fd967b729722246696b5a2804c43a0fd172847e44a4d3486b7246ff7556430d80c3a7eae5acd0b84939c91c72e5c983badceea171048a91dfbe49abdcd6b4ab5de74e1d2f0e9ddd9169d631f250d4778b3a6f8df7742eca0f7e975bd6714b6d8055bf4cba88f55384155382485b4acb1e1a8aa57e2856c7027840a1ff951123bd86acdb3f53a5cd89d7cd1d5e9f0f80d1688ecfbd76517ea4e992e77fa3d7e88f7fdffa4b2046ea16271284337a8314829ae92266c007f8ce8fb0c6b6d8db649b3169d18c357e9b88de61bb796796ec65c5f6903386a77be99481aeabf9d0b328422d51a99926dbe8111b0be5c9c04f6dd6d99d8db42eb58d003e335e23ae1be8cb9f492c788892d9165b55e8f07bdc88c3e194d00ddc38d110fc199ff34d31902d9f309704b1a9e42296736b29cd8631865518eca963cfe9f7be047b8be5ae8c8e8d56a978a9b17c8a0a80f4aaa90728a53d4e7ee9b7d1b1464973b60938b6801fa11a7b855170fb587a16c979bdc2455d0328ab4194f7f6fef7e31dad6ae3814b08b32b02703fc7acbd49464ddb31cb1393c1b6cef700ae2303076e1b44c0a1403d7125a1a6176950cedd724e84544084790007502c94997cfb5f28f6e6630f0c66d54f8dce4a6f5b89f68316c6d999f78c6083c866bb6301f35c9a4f8a13dba0339e95ef8fd4edcd3f52bccc3207e0dfb8838b2c1298c6784de70c3c5ac5567de821e7123154c18762fc3f6d0c4ccb6e1beaab8238e8a6e3754d19303e532f2a4754813fec6c2408cb7966867f3771b4be412631f618327eee73dbfdd89fa07a8b9119c0cbfb43f4744fd9bb57cd393b4beee3cc37a8347422b0a176e151aee7edc053e70462fcc29764da98a905b968b1e2ce0e7aa3fcebc2dca5f0c65e00af418ba4430832ab5d0d2fd071dc1ead1c07963de77c2feaee83fc830717c14ca4389652fde375a22bce0abaa1d91fcfdfa063bf089a5ecf7a1d2028c38060d5f78540a952eda8295436ee22d1206e616097797781b99a46d0e611df16b0b9fb6337cb208eb54d9318679c73306d1d1c08b98f48798deee38df1339a57287ddccb324ea606d11b99d748383dac425643103c0253e48530ebffcf851ec1c04972d6387d474d4145030fc30e8d32f58ba4c98eed1702b03eba71d002d73cff85c381224446baa13d487847cef97a7be3ac39c1f740374f8558273659ec8f06c26663c9a84df53f592010575b69eb696b16d4e8af34a018d8d8aafbead6924077210ae0d15f1cf9ce8a3492f09f2f25ab45ae45a9325687183e4f336f9a81672b5b796c15f9d751cb77747a54af3628aa4966640f307ca6823745c6d19e91438ddc1aab6548020be5fc643fac93b0243a085d2fa69fb8041dad10abbb22c06600c238f15962bd333450527e99ddd055931365e0c5c828574a102e076f729565635a4ac03b8da92a164e9b166aba81dfb6983bb14759bd59ad31a800a41119fc63a5bd19677f8759c9958731bf668815d0fc8f635d68d327dfc2bf4ca2f915658a2f5a6efa36151754f4b2752fb37894e29d49e9096ad7d7d406afd3821ec2a7db40a81d476a836ba1ce3b4369eb07cfdc2ef9376a8b35290810112101ac0171fce9f5ec353c00acce6956d351fd583a28b9156a0d83c5a2bf5b8da59229fd2831c8599a04646be34c39370ba54c9d1ef990b38fd3be08f7b385865bdf8d37d116d2cad5f90cb05759e0a7a93dcdafda7606c9677e34420c29eabbf9a9f7ba8c74202818c8580db5216ece31a198bf9a72e186b4877d0c3fd1da42378df68f38abae693e0c8ce76fe4656f761b63096c7c0df29b90a300cce139d246a3ec124ff36d67bb5e5daf9a8afeacd5e0a77fe61e101b001bf6c5951cfc40c4a8bcf8ec32be90ec685141c415f62b6edb7f0bcd5822959b9858ef871f01c3d151c23bb4a0b20df4c5ec868562c558220bded438de75162822bcee54483848de64ae6065dbf06187092f55b8a955eb4f72713ba136cc7286b2947f6f1d546bdcc015e89145e9645f8a960b472455dfacd0a5966f76f03ee754f6a38262dd3a1d3ba65f2e37bd678797c7ea90b7fb42ad20c9990b29ee0c110ee40b446b07af03b89d04ad73e8ec855ba713da8300000",
#   "ToString": "CTransaction(hash=7ac908356b, ver=2, vin.size=1, vout.size=3, nLockTime=0)\n    CTxIn(COutPoint(1584e36929, 0), scriptSig=1600140099a7ecbd938ed183)\n    CScriptWitness(304402206456952ad36556e88d6a4766a99ec0859709d8b58294c1a98c2936c12e9576230220644f632edb324a561f0578115992a2466df9fd4ecb62b5533b4866bf2d6be1f301, 033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a91434fbecbc9786f628943d2abf87)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a9140de6434adf2f3912732cdc20db)\n    CTxOut(nAsset=b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23, nValue=0.00010000, scriptPubKey=)\n    0100016561c226356a4c21008ca00dd9ab8691c223702a514b6b93842708478f95f51549954fa74abbd2265e6cc687ed4d1d87aca8026a11658f4def3e2aec7a4f6631\n    601f00000000000000017d288c455c863d9e65b8e4c342c391c7db9ae8c2a83f80aa20a38baf99de1c291a6bdb4a52858c78b63c364df1a171173618018a03ebed94fa8eb65207288cf2c5d5aa5d042e23324a3ed91859f634b726b98e8d4d1921ad0f71c22c5d8caf9bdc883d11b3d649b50f39af0860ca2ce0f458f85c8cc9a641e518e861f7ee5a9b23284808e5db99c447c4a4dd205021a87f8401b90eae2d758dec2e39eb2b3df66cdc6ec645b36d3b207b437c5416ebe5793024a65a287f449f39da92e94c481e398bcb9c6ac60dfecca40c34386585134e92ac87e739cfbdca988bc2e6ff295fff176e4578c65e4ae2a9e83cae0429d04f61b2a577d15444422df24788505029b959cb1c6d51102926358127215db3cf7d97f8bd866ae3acdd168e8356c94f6176830ffbd5ac58310e2670b90c9d3ecd1a67ac67ea3fb001426bf421d02acea87967ab20173f9e8ab34cb5904b6ddf4666fc39be17fbfa34930719a61ea1ddf6555daa3c9529542a45f9b53c155e69c87bd2ba831844b09d04bb91de29b0e381fc3ce9413064dfceeb4ca3bbfce35edb80d51b0a45ecc59da29a0b85055a8d50c1f6094b1d44d5ceb92745ea3b3efb5543a4e013f3a77434e0b17c1070fa1e7e564e4991e84e4dd50b2b696cb54993532689ac2334bc3d0d31ae424aa2ce49741a38c1cde36c8ae2b8ca2bfd39f39c30d9700ab958252988f9d68489ebf738574f1ec4b98886810c4c05703d278ea7d1db14077e31df8d720e61720bc23c4efb2ae25cf4d394f23e5a619668ca191458417f9f67f3b12c21bc5a4644e909d1f37e8b4b0146a6d57a71d6358edb0d0b6395956b0cf7ab94ac43d7e4fd6360bbf3d88c08c206f1dbed95c3e3b8a0fb4815f1000a75fcbbb17df30b1964c32d772a9f9ffe4fcbd7b5aa87d428bfb8b3c1a1a9b501504c2aa36563c7209892a64417bb84d9ed99902cacf7c0a4b4fce6574a7f5f83e6ab0cef0d2f4bd4453a374ed31c38684510f7ad075d199d72b4a7446fdc90d4532abe665dde2496f4b8e97d15cab6580cbb0748d9ec52d0ffcd506368e0273c78bc762bebf63f138f98c868ec6b691054dd0ccfc515e1194ed46f54901bf89c24c4b6acb2b6322a9959f89f797467233b5c8bca35a4ecacebdf507976fcd0d74b8cdce83dac6339f8b84472a6479fb187829f31a30885fd0b5825bd420b6e436d0942b5856da7bf9f120197327123859f8308cf0567eb4427f0d4471848fe985c6308c9a0b59fa2023ede00df7e46c5605a082c4798070f30cec4e1fa8ae47f5f045bae74093d0f736c45fe66629e50308fead86e52b90e1de93990e039c48438b987f3083cbe1e1e774a8d28dc538ac685b2bc329f87fb437d28014be11d5b721f7a61befa7003956ffb1a01eb9b01e61ecae77064abb75fd8e9ffc64130ddbe6b531775b06bff7eec0518b7d9b84c7130d63211b9219f12829f4a11649325583b4dc45a78a9760ac94dd50052657b6649489586bc34446d13e7a9ffc8ad25ae3029fcb57704f25273817754d00019cb14fc4d658df2bbabe9cf59a74974b967846386141fa4dcb77607854348084326afb84072353ad66367641916ec274b3fe8fab21f9431b2c885a1b52fef56de4e86d538c396e7ad9928818434da365f74973e7e640f5c291cfc452eaba3db2be4163df4db373398e17a9203c861e1cf421f0724cc6265432b45e370945c67771d94b2716cc751c8a4f868542fafd91d429ed6d149e9f1cb0bfd437d07e52802a480bdb91bfb8ab81fb3fd54523b7a0a5b845509722b828fe198d7743994956f1f17fafb06253afd87f44be9fbecb9c2df1b3a53a51b89eb334ec8bf5f140895358dbd6fc92475eaeef577bb47ed0f82ddbd320cf3574f9f41402980f632ce6a427ee77c69b59ae345d34d091a47fe9e8f521cc210ee20edb124aad650b1cb5699618a8239f61ebff227ae03971054b2d1a97d4297f6d26ff2557fab6c7c205c69e1d3da2bf69f8cf3600f73a52c582f7757e25f9ed503dc4ee5ce45927d5f852677610f398d3c9d94829e3531aa59265f54a6926ff747e14a3651af27ac08bd3f6e71361ae17433ea49a8050f4e3ecfd701b61768de48249822c4f99c93ce913d7f7a78bef1453e6ef0579a9b5613c7571660966bafef2452d11ac409a9fdc64141cb8faeef4cf99d502f832d1a8202037c1c0a2094b51d1eac098802086f259f0261cbab07d692b88e4c4b9718c764c325ef4a0e604fff72f2f2878597cc78bb8ebae0759961f78c0a09cd270fcd51b2445d971b22e8c58c8c6b2970171c9bd0e8b514135fd9179f5d96e54578267d6a4c444ef7b2422090dd442c530b11bc0a6cdfc0435c1f32a16d7dde6332323a12559c0d2501f6bfe8d8f00ae141f8e490ca9ca165616623ff5b76847f8bf189faff85c1a7d54175970c09cc379b2cfbe4fe2632bd920d49d10ee6aa2559131a87915f8551affdb877ad7e8ffaabe4c422d7ed20b80e5e75bd807fb56cc40becfed149ed6d2e507811c24bf350a42dc9e6864163c9c3b99fc51739579b9b09bdff2a92b04263ff1521717565d1f6a134cd66b300ce89ebbdab96df38d8fed3e9fbe345fee891d3cfc82fd8f50871dfa4ce2ad069d1819feef1a4e00ca0adb7ba5923eccfa2879ef1754509fda6db8d1ca244a2e631c72f647e50edc069929cd1acbb3be3d5e5a752836dab795e48a9cbb5472394bfe32d42cc387cd780f4cf05051bca136b53be3f3a9c4637ee574d607195b5eff3d232c186f80d486fcb01b7d9d55218ad43ddcb15e4f0944ecf42e1a87dc645d9f6fead7588ccc6afa64a6d3d90cbe4ae122cb6b773fe6441fff4041c24f894a94bc9f39ed851ef55ab8ebdf440da87f3ca7a796288b71c93267b78a1ddb9413b94b496a878534724bdbf3ac642e63f607c7ff83797b7386cb1adb88632f85f0e8d5caa0f93e1a9dc0d733e09c6774c22d887e5bba69e9133b28652a7db73377f5ea27d409d5bed9a0cb844b9cdd8cd703c32bb9f04a24658cdb73d8726a03ed82c27c2e2fe98eda22b5ea828a5f3f53149892d3208564fcc8171faf59cf4ed071de10d84b126dba9e3ba68558f88a038079bd9d8ec79bc4391e6d328208ac86530bd970875759cc847def42104dcc6787dd89e1dd1d0564bddadef7679bf77afee50991713ecba514764a5663626f5935fa9fc57e71a2d8c0a7b5994ff22b4d60c34f8b40e9e1a3765f829804a3fc4f003876da5624885fbc98b5add54ee6ff70b9a9ef284af4498c49e7ca040a9e0c3fc7ad0daa5a092785ca5da3de40d7a689c676ed2122127e5d15313d5b6dd66a12edf56c0347fbab26471b3113149abd03c329f087d78a328e337bc7bc796bc98ea764e0f7d9f468554ad09bc8be415fe177d3cc7c53d1454c2ce8498998450fe528a0b2692cb7f677aa12639e4b77c79bff2f31b3dbda8ef74f02e514613c84ca6847d93cab83b1b7ae7b3c6871c152c71afdd0fad2544f443f5cfecc0e4c4ecdbee4094023fe19395ac3c44bb5ed4e5c190542036d533e2ce9b712c985448ef8807ae78928440bbdcaa4876f106abbb3befb5ba58dbaf086e892832b345e670ddf6fa6d5168c8b3215e\n    0100015462b4ad56d7475b7d0b0e34795ecd4a2ca35ee7c766db384dfcb059e74779fd453d184e8f7a35631a27d399db4916894aa61326a6faf8efca0e159998657a5c\n    601f0000000000000001c02984316a1be3fa0f73f94cb86894c525b521316cedb17246c4a68524af74f70927326f2ef2fba9965fb9330e6d9a406b2c9015702cfbe890d92283bbf83ca789cceff734c8d0e28be3ed50f462b5be2cd622fa5da620c77634c931521772c2720c36dbc03ebe7dea94294ebad9727b3a9a4a3ff470739b28a57a5a92a9e1d0ffa2a97898178c5fbb41a780d2a4f7e2a78890f62efb55e85dd401414022034161c10eb5fab58019b14d2e464f3b1d6300618036a1a4cb16c666f2342c004e181688c9adc419c4996840daed98ea40beb7eb0941b6a05d80b563dbba4fc284901f6a824c5078fa4b8fb947e76dc7052acac948944d72ee8767bf2511a02edaba5ddc5d057766c4a1d9dc6db274f973161b3e62f523cdcbf668916ff96ec75142a48c82a48ba5f6dc18535c9f46be2bdac1a9f6b7cec577772b88abcd0949cc6a83351001f6a2d1b34487ed79492779a5559bbabecd0c85e451400b895d6a477a5a13d3288dc7824c791d79ffa862fd3adeeb3d5261deefc513b58dd8af0e1bee96da7caf1774b3527038b0a4619a96f8865853957a48f1ece557b8f60125c526574e36e324f6e31fe7b57133ecea298003e3659c0fdfacd5a6dc8d0b461fe458daef6d40a44bedd9d0b1db75580c96dae2f323a60e1ca44af7560736253ebfd59667ec8977d7d56372f24301dc364bfe51e4b7cd8ed33628def79bf09f08c8568bed73e1fdb4e40a1281157ab084cfa7777f45944eeb242749bb8fe2e8a186a12b1b28c223bc01e9138fe0814748b757913a7ed446c7af7c8ac7c5ee1ec86d739a8b4226b25ced682685a40e5950a8da1212c3bc795326163c1687e4a38173fe900846d66bfa58d9fdf961f5df70b854d5e5307ae535b83d616b06ef874292b5ed3a5cae182d15cd6d3bd42bd281fb49f5f3f3f98b18c9d23e1e852784b1ec152982442cf3d0acd70d3eac33b34fb4fb174de1eb5ecaa2e9d4741bfe4f357ef5b48e4991a24863a604b17a28d57e225adc7c86aa86f5512c08b594349459416e97828971b1d8f0531c789e07b8fd21dec537aef50356407c6434fb60608f0c8b200a02cd7dac8dadbde4d1c023a0ffe4c215fbd02049edc273c74c06747557608a5a9ca9953fd4dbff3dc76e93e03dfe562431a8f7e40fc3977044ba76b13e1b6e994d32dcd7ac84e20030402f3db570db8b8e604458e7c1d9c739e0b44f33e5c93fa32fce296105b2074ba68bd5a4a53d4437e52ee3dbeddb36ea94d200f76c15e822601b959632bad778a58675c3a706a8785e649fe79addb8112d7aa1e31878bdfc4e13419ba85a29c8c3f63b73f9f86f805ed6d8c0a64d6b28b0a988a710d4edcdf2c184a448f147158cc8363b1c64f2bbe7154029dfffbefb7fe3f464a9b68acc461fbabedf3f6b3f903127930c9c5f8246fabc1719d5fb2354057d20cea0a541cd09b169dc04af8ac576c31b378bb522a6b35cf6e2bca2fd967b729722246696b5a2804c43a0fd172847e44a4d3486b7246ff7556430d80c3a7eae5acd0b84939c91c72e5c983badceea171048a91dfbe49abdcd6b4ab5de74e1d2f0e9ddd9169d631f250d4778b3a6f8df7742eca0f7e975bd6714b6d8055bf4cba88f55384155382485b4acb1e1a8aa57e2856c7027840a1ff951123bd86acdb3f53a5cd89d7cd1d5e9f0f80d1688ecfbd76517ea4e992e77fa3d7e88f7fdffa4b2046ea16271284337a8314829ae92266c007f8ce8fb0c6b6d8db649b3169d18c357e9b88de61bb796796ec65c5f6903386a77be99481aeabf9d0b328422d51a99926dbe8111b0be5c9c04f6dd6d99d8db42eb58d003e335e23ae1be8cb9f492c788892d9165b55e8f07bdc88c3e194d00ddc38d110fc199ff34d31902d9f309704b1a9e42296736b29cd8631865518eca963cfe9f7be047b8be5ae8c8e8d56a978a9b17c8a0a80f4aaa90728a53d4e7ee9b7d1b1464973b60938b6801fa11a7b855170fb587a16c979bdc2455d0328ab4194f7f6fef7e31dad6ae3814b08b32b02703fc7acbd49464ddb31cb1393c1b6cef700ae2303076e1b44c0a1403d7125a1a6176950cedd724e84544084790007502c94997cfb5f28f6e6630f0c66d54f8dce4a6f5b89f68316c6d999f78c6083c866bb6301f35c9a4f8a13dba0339e95ef8fd4edcd3f52bccc3207e0dfb8838b2c1298c6784de70c3c5ac5567de821e7123154c18762fc3f6d0c4ccb6e1beaab8238e8a6e3754d19303e532f2a4754813fec6c2408cb7966867f3771b4be412631f618327eee73dbfdd89fa07a8b9119c0cbfb43f4744fd9bb57cd393b4beee3cc37a8347422b0a176e151aee7edc053e70462fcc29764da98a905b968b1e2ce0e7aa3fcebc2dca5f0c65e00af418ba4430832ab5d0d2fd071dc1ead1c07963de77c2feaee83fc830717c14ca4389652fde375a22bce0abaa1d91fcfdfa063bf089a5ecf7a1d2028c38060d5f78540a952eda8295436ee22d1206e616097797781b99a46d0e611df16b0b9fb6337cb208eb54d9318679c73306d1d1c08b98f48798deee38df1339a57287ddccb324ea606d11b99d748383dac425643103c0253e48530ebffcf851ec1c04972d6387d474d4145030fc30e8d32f58ba4c98eed1702b03eba71d002d73cff85c381224446baa13d487847cef97a7be3ac39c1f740374f8558273659ec8f06c26663c9a84df53f592010575b69eb696b16d4e8af34a018d8d8aafbead6924077210ae0d15f1cf9ce8a3492f09f2f25ab45ae45a9325687183e4f336f9a81672b5b796c15f9d751cb77747a54af3628aa4966640f307ca6823745c6d19e91438ddc1aab6548020be5fc643fac93b0243a085d2fa69fb8041dad10abbb22c06600c238f15962bd333450527e99ddd055931365e0c5c828574a102e076f729565635a4ac03b8da92a164e9b166aba81dfb6983bb14759bd59ad31a800a41119fc63a5bd19677f8759c9958731bf668815d0fc8f635d68d327dfc2bf4ca2f915658a2f5a6efa36151754f4b2752fb37894e29d49e9096ad7d7d406afd3821ec2a7db40a81d476a836ba1ce3b4369eb07cfdc2ef9376a8b35290810112101ac0171fce9f5ec353c00acce6956d351fd583a28b9156a0d83c5a2bf5b8da59229fd2831c8599a04646be34c39370ba54c9d1ef990b38fd3be08f7b385865bdf8d37d116d2cad5f90cb05759e0a7a93dcdafda7606c9677e34420c29eabbf9a9f7ba8c74202818c8580db5216ece31a198bf9a72e186b4877d0c3fd1da42378df68f38abae693e0c8ce76fe4656f761b63096c7c0df29b90a300cce139d246a3ec124ff36d67bb5e5daf9a8afeacd5e0a77fe61e101b001bf6c5951cfc40c4a8bcf8ec32be90ec685141c415f62b6edb7f0bcd5822959b9858ef871f01c3d151c23bb4a0b20df4c5ec868562c558220bded438de75162822bcee54483848de64ae6065dbf06187092f55b8a955eb4f72713ba136cc7286b2947f6f1d546bdcc015e89145e9645f8a960b472455dfacd0a5966f76f03ee754f6a38262dd3a1d3ba65f2e37bd678797c7ea90b7fb42ad20c9990b29ee0c110ee40b446b07af03b89d04ad73e8ec855ba713da830\n    \n    \n"
# }


def txs_from_hex(d):
    return {
        bytes.fromhex(k): CElementsTransaction.deserialize(bytes.fromhex(v))
        for k, v in d.items()
    }


def unblind(client, txo, wit) -> UnblindingSuccess:
    nonce = elements.get_rangeproof_nonce(
        client=client,
        ecdh_pubkey=txo.nNonce.commitment,
        script_pubkey=bytes(txo.scriptPubKey),
    )
    result = unblind_confidential_output(
        nonce=nonce,
        confValue=txo.nValue,
        confAsset=txo.nAsset,
        committedScript=txo.scriptPubKey,
        rangeproof=wit.rangeproof,
    )
    assert isinstance(result, UnblindingSuccess), result.error
    return result
