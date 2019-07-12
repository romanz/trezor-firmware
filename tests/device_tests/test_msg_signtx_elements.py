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
    verify_rangeproof,
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
    txins = [
        _explicit_lbtc(
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
    ]
    txouts = [
        _explicit_lbtc(
            proto.TxOutputType(
                address="2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr",  # 44'/1'/0'/0/0
                amount=9990000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        ),
        _explicit_lbtc(proto.TxOutputType(address="", amount=10000)),  # fee
    ]
    with client:
        client.set_expected_responses(
            (signature_responses(txins, txouts, sign_confirms=2))
        )
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
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
    txins = [
        _explicit_lbtc(
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
    ]
    txouts = [
        _explicit_lbtc(
            proto.TxOutputType(
                address="2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr",  # 44'/1'/0'/0/0
                amount=9860000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        ),
        _explicit_lbtc(proto.TxOutputType(address="", amount=10000)),  # fee
    ]
    with client:
        client.set_expected_responses(
            signature_responses(txins, txouts, sign_confirms=2)
        )
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
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

    txins = [
        _explicit_lbtc(
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
    ]

    txouts = [
        _explicit_lbtc(
            proto.TxOutputType(
                address_n=parse_path("49'/1'/7'/1/0"),
                amount=23590000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        ),
        _explicit_lbtc(proto.TxOutputType(address="", amount=10000)),  # fee
    ]

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
            signature_responses(txins, txouts, sign_confirms=2)
        )
        signatures, _ = btc.sign_tx(
            client,
            coin_name,
            txins,
            txouts,
            details=proto.SignTx(version=2, lock_time=7),
            prev_txes=None,
        )
        # store signature
        txins[0].multisig.signatures[0] = signatures[0]
        # sign with third key
        txins[0].address_n = parse_path("49'/1'/3'/1/0")
        client.set_expected_responses(
            signature_responses(txins, txouts, sign_confirms=2)
        )
        _, serialized_tx = btc.sign_tx(
            client,
            coin_name,
            txins,
            txouts,
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
        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            details=proto.SignTx(version=2, lock_time=0),
            prev_txes=None,
        )

    print(serialized_tx.hex(), file=sys.stderr)
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
            client=client,
            txo=tx.vout[txin.prev_index],
            rangeproof=tx.wit.vtxoutwit[txin.prev_index].rangeproof,
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
        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            details=proto.SignTx(version=2, lock_time=0),
            prev_txes=None,
        )

    print(serialized_tx.hex(), file=sys.stderr)
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

            output = UnblindingSuccess(
                amount=out.amount,
                asset=CAsset(out.confidential.asset),
                blinding_factor=Uint256(out.confidential.amount_blind),
                asset_blinding_factor=Uint256(out.confidential.asset_blind),
            )

            assert output == unblind(client=client, txo=vout, rangeproof=wit.rangeproof)
            # Note: the surjection proof is computed on-host
            assert not wit.surjectionproof
            wit.surjectionproof = generate_surjectionproof(
                surjectionTargets=input_assets,
                targetAssetGenerators=input_generators,
                targetAssetBlinders=input_asset_blinds,
                assetblinds=[output.asset_blinding_factor],
                gen=blinded_generator(
                    asset=output.asset, blind=output.asset_blinding_factor
                ),
                asset=output.asset,
            )

    return tx.to_immutable()


def _generate_rangeproof(vout, output, nonce):
    return generate_rangeproof(
        in_blinds=[output.blinding_factor],
        nonce=Uint256(nonce),
        amount=output.amount,
        scriptPubKey=vout.scriptPubKey,
        commit=vout.nValue,
        gen=vout.nAsset,
        asset=output.asset,
        in_assetblinds=[output.asset_blinding_factor],
    )


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


def unblind(client, txo, rangeproof) -> UnblindingSuccess:
    verify_rangeproof(
        confValue=txo.nValue,
        confAsset=txo.nAsset,
        committedScript=txo.scriptPubKey,
        rangeproof=rangeproof,
    )
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
        rangeproof=rangeproof,
    )
    assert isinstance(result, UnblindingSuccess), result.error
    return result


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig_csv_1_explicit(client):
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

    txins = [
        _explicit_lbtc(
            proto.TxInputType(
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
            )
        )
    ]

    txouts = [
        _explicit_lbtc(
            proto.TxOutputType(
                address="XDLMKBtydtPVx836Rbi1yvseKW11yFx4TY",
                amount=12_3456_0000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        ),
        _explicit_lbtc(proto.TxOutputType(address="", amount=7890)),  # fee
    ]

    with client:
        # sign with user key
        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
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
def test_send_elements_multisig_csv_2_explicit(client):
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

    txins = [
        _explicit_lbtc(
            proto.TxInputType(
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
            )
        )
    ]

    txouts = [
        _explicit_lbtc(
            proto.TxOutputType(
                address="XDLMKBtydtPVx836Rbi1yvseKW11yFx4TY",
                amount=12_3456_0000,
                script_type=proto.OutputScriptType.PAYTOADDRESS,
            )
        ),
        _explicit_lbtc(proto.TxOutputType(address="", amount=7890)),  # fee
    ]

    with client:
        # sign with user key
        client.set_expected_responses(signature_responses(txins, txouts))
        signatures, _ = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

        # store signature
        txins[0].multisig.signatures[0] = signatures[0]
        # sign with second key
        txins[0].address_n = parse_path("49'/1'/2'/0/1")

        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    # TXID 60a50d9161a5df8e978c86ece8b23d76ab339d07235a37b5ed26094e55d3c762
    assert (
        serialized_tx.hex()
        == "0200000001010d0ea472334512d78b4951d4ffb7e7520db47999f99edf53a78d9e781475e33601000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000004995e4000017a91415c53bbead6a347ea228ead57f54b49888a8f3c58701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000001ed2000000000000000003473044022078852a3c2cb543138e56577bfe4a26f23b08331d0b587101509f50ccb73b03f80220461d196b401e24881c711188a4de7c33ab0f7091c4339f8f5b6dd344451fe5460147304402204f9f4ebcdee6697c5278ee7a142779ce9156168c2a950531fd6d7d6451b5a7d5022013012ab3606d81bfd12beada29721fec65775610c73f8a85396e4c7325df21c10150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac0000000000"
    )


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig_csv_1_confidential(client):
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
                confidential=True,
            )
            == "AzpwvcT8N3V4GDY6iMejsUrZ6ZMLRFh4sj3fywQmF1NwWX2yJyFnmkRYkEBwYs3JK6UybmJzj5Py5aU6"  # XaEtEibtM5uecf62yVpXiFMVhCkuGdkKAG
        )

    txins = [
        proto.TxInputType(
            address_n=parse_path("49'/1'/1'/0/1"),
            prev_hash=bytes.fromhex(
                "963118b8487b49c28a3931001ace586d977bad5a8babf97a81158899c049e578"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=1234_0000,
            sequence=multisig.csv,  # must be present for non-cooperative spend.
        )
    ]

    txs = txs_from_hex(
        {
            "963118b8487b49c28a3931001ace586d977bad5a8babf97a81158899c049e578": "020000000101695439f26a32c3463f2f9b417a57dcecbd13f8bf46c8ba44ad7b50bc379804df0000000017160014990cd08a4e725a566bc8ac21cac5318d79f3954dfdffffff030b9d8522eb5262e8bec26d005f73f6c18421e480124f2384aa77362eaf09f69814089465c87e380f894e369b405035d1d95122829f4146916c90398804260b4b7cbf0340c13d7bdf40fb88364e240c4496eecda9c471136236b10973056638755b96a917a914fb1731356772ce6c36b525d7989092c21e385bab870b32b7cbeb50e4c77cb3a1c916925d50e6df3c30472e5377f177f0b1ab07bc92da08fac639a935182073512bba6594ca4436cd616f63f26ff69fd56b5acfa9d490af02071d54a86f6135fccf499306c80ae8d7cbb804be5e8d56d9e2005ec672ced87717a9142f75e6a11f041cb4ec64f812d5d3959a9f935aaf8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000927c00000300000000000247304402200ea08e1f60a05e9fe80c9ec86a53e8efaa492384099116db9dbbf4758fa0b829022074eeb87f1bc3f581de63ab3b8323ae786439a6a5c2ce2a5c790f6d1a36a4b4a20121039e760c28a1573c8d5a48f17d7445112d539989bb02c3e6dd92126fb74e68d5a30043010001aa8a9b5c9540affed6f43d93186b83a68d728a9842ba117a0876e167bfef2f13a9868e98e846b7290e1503330b8ffd16c044bab1bb5cc3ddff45ba8a692d48dffd4d0b60230000000000000001d37201303d820528d844e97c515594035b46ec789e2cfdefdadde7149d46363d359c1d0b3b0a8c2674034561925d6a6fc038191b0b7cf720cf33663cefb8a85ac3fc1ba81df9cd88613b9cd465f1acb6a1deef77a0b566595023f2e399aee0eb624d1e7c7ab5dc8489eb376025267e4d90a0fd251917f028dc08c827074241b7b88e709ec2ce738e1ed666aed8a4c5d833199d1531190c98537944cd0c1a8594800d7d4f25b36c1c389148faca321643e84aa9a67707dc9f874e95d0c3844a8ae83dded40ed2790db851b25556b93e0a22b730d5492b88d1aed973b570f42bf8c094d536636225e13466058857bd98b2a41220ca9e73b21d7004671a22f1374dce525e92662164235fba6906733c1745c21839a59f7719517a1a83308b0cc311f4ca408329fdd18cffec9f6e1efdd9c958ba4a38cc9ab33ad88ad37ff659a15ab388c0748cc092eafd17d33aed04cbb771f594b6e4189044e66dec133a52f3a470fb8ef6b7168a7f66c4c3b3f4f33a86f589ba28cbcac04486420470985f09be356a641338e0358acb6625af61fad8e715a6d5dfd92d07661428b58e031dd5212d1fe8d0fb9dda9ee9a98ff97b5dd60c54f780a134b5bb03f61d2687b01323a8d64e818df1636a4505b9851c09e2f72f9559163f57b83d49c8df67958bcfaba06715c587339a5910a142e5b9058fa1c20948f2f44109cd4d0d1069410e7ee7f98c883f0706960af3ac1158a08339670ffe501898c5b079bce472ec6a828dfada52d4417132b984a3f369e02dbc8284a987f3c012ad5f3d642869ef6ce1f7e91258f60d309a740207685df6b2921ff984e45fe985c68a155f9cb72aa05ae25ea618706200c9b9b3d2a4149f84b179a7b313b1224a46189790da8345ff5b283c91bb21ce97c1b151463b5f721783e8154bb942e71ad8d0ffea4a9719c449f634deed80713b53db71064ddfd1471dd79e32b8946aa153276826ed1b23694c76482cd7ef0b5c42a36dd40188c5b50ec26f9375d73214aad0ef25dc1bb459bdabf1f63710b8f54fe742a24ad2e1d6eab841da3a15d4f734bcb8ec778797ec398bfafc6e871ec99e5e99fef6ac9c95b7961f1cc89aa705f8c07776a0334bf38c9256b8d12bff4faac5435455575e46036d6306583f7a6b84611830f6e8574cf29c36774a9471f5b15ec7c4636e0cffed51ec85fa1c2876d09cb0a9934e251e8ccda8cff518c155d7fe206301d995ec2f6bc7dfb1b0dd434c97616b77964517b93c3c156e0601a92cf04c9998390614f75397a8b2e57a7da761e6dc0cb55a824d0e056df91f284197aaae9990c4c276452d7a7d14b2d662b1c94737ca2b84f049b30ce7bdbe01b9a50521c4c8a076060a087605d8ce25c7ea06ab7a0d7ce754f3acf933622fb6ab5efafedc13558f8b38596213bfdcb1a68c5b662e048552049898654002a1aa8baf3fd5753aab3e41a1966d7046c85f6c5daa627e439c4087d61edeb611ea994ec823cc5c89d53e2a94339e1943197b62be27477236a751c18d8d046a14be8b59c29164e308a171e43d4cdb3e47da21c8a1b7aa1e4e3c9c2fb4ccbde1993c78bdb7ee1ee8c1fe220de9961243dc5088326bf72511659779a8d29e9a2eea8f0ad4eee2cc6d78ca624938066411ca197bcfc586803af1899b227445a1cd12e5af872f547ed5dbf404757fd87a0ab865b3338470406246c9c9fb0c00f0d0325b9c02ae9bec9ff72321a76e1e2874f8e015ec8ef805d1e4ba5fd840358a10af52519cbbcac415f57860d246c42252e2dfd08b6e497cc3539e356627160f4a34c5f94bcd0d11ef4da3b5e7d138739453f7a2dfe325a3d276de81d864d1d59d749d85c8243589d398eb2c409ee8577011424823b86b9653437faa5e23c982ea82e85b9139ad8f2c71a460e72d1c013b18146b11eee81175f4952eb7d933a3557cffdf35099b21e147af6b62dbb3ef3e1e89b82df48e44eb43a68738852be133d4904754e4c1ab32583ab96dd37f768777dae65b4fcdaaa365cf4ba6312bc219320dd2520c7013907c314b784c04010324f0aa2160fbde585b01ebd38a5bbefe7e37d3e66520be704c90b6a6941f9c5ca122817ce7f447b23829bd5c334ff1bbef93244f722f44f3b8fe3aed5fd28d4c3bd083f5ff3a6a573c99bcc8d3f6cefc850bee7735833770eb39661b7ab538128ca2a4ebdf8a7bf74aecea33cf9298f7002f4e6d6a7ddf060b66089107e657b8c8ffdf5590cd7bf1f6f98b671db710421b27372ca2c906991fbcaa8e28426ccbe66886ae7efc06fb3f714408e656dec084d4e3e8cbe14c65d528a95fd3200da69a47386a45471861fce8559aeb25d617eb21238e34f93e1a133686c77f300cb9add3d39e4d9b95ba90ad9ce2087e3fd31db1db2bc890430ff72c2362e3e15e52c9d53c9d14f19ccce20395a4a8c2df06f1ef2c5209f3cc9408c38371535f0c5ddc9d8742a3a1a939959a49fe05ab073bbcf5a559996763c5b44cb61425094b3282b3200030090d32efe9e6606faea7e499c19a06e886ef99b4dabe19e2bec6bd74a7a94629d43e487afa1f9604810f6fc3b3286ee94e6a9658325d128c0d84313af9b87c44b724067925680b9d2f6c2735810203ce9e612bc78ce333f23105cf897a97551998617a0ff0b328f3ac06fc778fdf641c8c8f8d312052f5c2d836b057ab6c7e43ff1b2271d16138b659053b3a5640caba512a53dece72cf745628d29c2ca5ccc8098432e90f4cbfcf50489d5f7847b088cb6c1510347749f939190ed98ba4ed88a40c39d17d5f08001b39ebb53fa0b38a0be94b93b7834f31fcd186fc39f10d672566d32fc3a15a7cd34248d22de5c234dbe73074332967b6ef7a8205de57d2c33e6b9498b1860478dcd59a8b503bd726809d6b9278aa8b71a3f563649708ef6042bb27c927f6b70ef6ea8eafb5b25d0d9d480f7f0772452177e6ad07d3bc892c8ccfbf88dee45b780ab177f8cf5ab91ed03fd66b843d5f4f43e2cc8a8ce6d9d8a1c963f22698f9c9d29954ca4a0a46fc6f45fadaa23ace34b92a4caa2e3f5976820de4cce31a4bc2dbc498b84747b58e509da546224367d3301b74c5bf04075c1512d69280aa0b96d229fc21e7a33d782f0e2d5f6a3c9760331dc5b81f73cf8f6b074c16c617c7ea26cb3bee2ba88d12913658b61d88d13d9bc47b02523a3d3f4a2fecd90c94d1012d1d292478651ce78e2c9851a8fa212db6ce9df5bc405f7c57513cfbbb2f21d3cc144975656123f64f851b007235cd28e0c0f35978a377c970670cc66452a7b67b203e8ab6a4a13cb016b43d838266a8dec40694c3b9cedaa5d0fdbf93a2d0f2f143d67ee3eae4bb5770d2dfcfe601aade4cda4eb349886d62511d9d181c00969b42fbc7c0f2e26b9ac033d68c95ea8c0b380670f149a82b468cf3a5091ae339b86e2a8f31259ada4f307c3ad44cc8168601fbf9dd0fd17d290ac36b2cea6481f0cff27f4b57441e8f60bbc44f36b48a047e8c148ffbfb5e290a525cff308af81e50f49873022702bea3c79d1c2cf327f9740573c76a01e947a84e8276a4c5b379dedce52aed22f0f4b1fac97a7c7c97c41bec0bbf5f3a5a3ea90b451bb3d5a2f955b2b34422d6153d0da5bac763b24d49220ad48c7a3904eed8fb844b87b3298a49294412037810a9c02e01043710eeef06b8ad6e0434081a86b7291ba4c46e913f4edd675b434a752eeb1d350bcf9b0c47ce09fc0ac03a5a60353d64a8b75ee9856c9285759f90361ccfd09f407cd5a7df3e0feb5533aa569f544560eeb172debcfec7082df450264e9c0e3d607d0d436556598ac634d4bbab6704536a0b443c25a7ab538f1da5cfb51b806ec51e00ea28b69fd913729dc350f1e8adf8629ab4149e925d78a347defed75c2cc5393b53771d2720a727028e3a80da2e11355d977823b6d2d5a5e33d6e8385038f885aa91bcffc03de62f217d24eddafed6b1e6b1ab25421f8629a9c360fbf88524690aa11e454f907f11ea7fb1e0e86aca9deacb5d3faf18c948ab4c6b9d9fc2f38894369af5f15294a25706eeecdd116923a0af1f069c8ff43010001f39e5143c150e435c728f2a9129ad049415d09f77af9a81fe0bbb6cef9603e1fe0e56fa74b77404fadea2b23946eb599d3670fdd7d057dec30576a9ac8a3e7aafd4d0b602300000000000000014acf013486621a53d5d2bdebb13334073cd376ba66f47487a067ce7fc46b63375eafc2179ce03e9d5935db7bb56c6f9ec67156d56c1c789fc8ab86e1d89b28ae399b02f7f7bc131fabf92b16818e689c46c601d91ccfd06bace870a4cead41f42688bbea73c0161473c58208f678b61c9cd76bc89c497f0fc582eb4ecf09cc4b220c3a4c05f7296a5fa22135932bab51e161a43083f232ebda339d1061d30d75b43dd04b041ea40fa4d9435b2efc75e0504cae26ba9522fc11c0f984ddc487d301648a7e31b5c616fd4e1d7942e8224a9cc56db8b79ef9ab9f6d41260d6c27d59d6033625814ba154a3359b434308a901d31773737d7b7016657c1a4b704f8f101b18a462792c9dbdb7e7b3852e75931a92b88ff08bb90d3a7d0e4f06518d5430770edab7bd3dbdb1b01c90e6e0599b0b229707227cef3edf8755bb06ca271856d462470dacd26a9fac021a22813c2d7f8867e8157c8811350d86c431698bea5761c6a075c49acbaf7919149e00e067c0b219a2304f7e1a325dca5723b2e328ed958667caf022e0ecd74cd729592e3e0f2ce2f847b430323d15157b69aee0fb2f5a262b12b5c7c99e924666bf00d968bbc675f16f2ee47d3299b2864c125ecb2d5f0bc3dae281280b5e64db90eebb7f8637e3fbccfc466e83b36bb36ce30ab584976aa563fccd75a93f3a37fe4e268bf9f412625e88f3ac1c5eb619eab17035eb15ec1c0ac1d863f8a3fc61c10ad8aae4e94967c5498547fd69fcd168bd4929c0e0b8bcd83158b31f1d44d5776716d0ba0324c5cb3033bdb0531ffd5662d24f42cb3bbff4a05e657631a1e73bc6f5050aeb9c3a6e622d1d9b32a278dc68d2fe64f6393b8ca0c98db978a835bf332ff8c77fd3b6bedc2ad08b5079078953919d91eb52903f08d841549ca371474b66fe757cf5b0563ef3cfa2276ffba26b713cccbc7d4fc9c1a2e5795b030c25190b4b838e84e80af8973acc4612d646e1fba0b11a16b95afeaf33ba3ff70febd29456cc522f25f93a659ffc4b656b3ddfc0782af7d5f6c83526d47854d33fba5c1e3fe235f8dd125014280ccdc445668bae09450ffe42130ada0dd89ff65aa8c269937d70515e8412aaba7bf57923b5e01aad1e793f596e2240cd74fbc22bf8881fbb1290176f64b99c93b9ee8c8d6a2a07d9665de12e39c7d2e7d00492cb69406a9b58f6da0cc38cdf09415983f708f46b28bdbd22e82176e8fe85ef21471f62a045a978c3a7692eb840c4cfea1d9116de561d074ca80e5138deebbed6f6adb30b50ebfb2bc973a41d8ac9bc13e07e90d7b0531a62850658e372165a778c759b53cbf5fb50a1af860761c962e561879838504fc6e4ff33f0b794f80a5418b67ab7d9effc83e484cd951d5d9da93ad2a4490f7004cc9c11d8a3c69b7dd45fcaa4f9ddcfba7dc81cd80b5d8f75a64e0a4aaedabe986d682168d71f73f4ef38f691a27359209aca5775bd7eeb3f3ca1d8061f6d76af4654266a6d73667b64a3078c06daa7cc230de67035bea67bc0bbf7a6041feee2beae5d8e7471b8a66f4d8452562ba6cb81293a456e966177fefb64717968519cfae2739ed27abd41927e6ea5759b84ed222eff1491ce21e7b0d49800c6a2740283068049b6e05ee3981895c1de72219266aa95e4214e175578e5dbb802a7ea90e886a013f21d3f4cf62950e45f032877648a83f977a26c5726342f1016812ab315c477423d2fecd9cda98e311b170906ea0004973423e8a91658be8f7583a8b3e5298e341c4ea155774f5c3653bfbc129ab5324f74edd800e08321f26affeec994e007616ca26ee0c799e1fa2493357666ed4b98d5e63c54a8d46dc104f6f2c5bbe6c00f9d661fb722fb2c7fed2eb771ab984de07e8be7e2aa8a0978e7bcb7e73ff92dda52dbe4f6174dc0a5d7126409eae0e3e934725bea8dcd8d416ae20659684736006910081f56559e9b829f916d813b4733301a0430e7b8f30f9d50cfd5027d9a378cbedd37623dde11c6c8f2a4e99496023a34a3f6008e5a35773fe6df19d060341b668770b1ebc9608894d5485d22c642d4bd2623ff80b20607585070edfe47aad84a3bc1ba59d2ca3489555decf1a39b159271fa25479c23b6d71b8521d671cf6df65f9bdb47182856a7792440f6922a3f2cd0fcc5d145262ac80f2044f3a4ace74f947eb8a2742a42009dc23ba41bbe71746b16e6538726c18ce339616f286780fb6f62d676db039569f7558fce2e0ea7afce6efb91acb954fdf29c95ed39671944b4aaff735331b2c8aa79d254d137bd24f8f2958e6a1ab76b40853ebe2481ef511dac69fa063c172ab1e9477e037185c4ce6d8485a7e39024c93ebb51b65b92c784b3cb9c5272d1f8d98ee7dba187b911b03adbdd26c07e4626bcddcfaa8d428dc8a0efe1c732115aac94f1f36962982842febd2cad1daebeb59bdc7c85a9c4b864e42260dd501ac15b014b03d297e898eceb2ca46554b9ce12335398d6ac23fd350c44365313ed668b016d904c2f511edc0f7dd5b87ae662bc0050065d5aed8d98cff48d7ae2cd833e49bafc0411e146e6ab2420ebe3128b691c2ea879d004ed5443cf49625ac510b61c8cebafda598e63e6b519ca975e29c346ce3e1e009145cb3d351942d1a4c8b52603026292d465ca33ef0efec78436d20bf22955a38d3aa3897b21da29bf1faef84fa6a411875c11f1b52dd1f62585688b643e2f75fc5b8f72d12516378b887342b9be6b676c68cb258e6d21ab6d54566296bdf3aa4aadeb92e8c23ca6b0af0913124a2910d291ce87d88172e6245fd3a45728a4762a48c9ac1375b330d9143794b59bcb782dd39d97bbcdc16fce228926e4e2f310fb11da2db69c03ec5f0b7cbdef29a4fbffda51afc5893a6cc60045a9b98422136e7bb1c89edf37c5c2545c903efe746514d946fb218d4136b9fbe88bc119f09a8779f1c7d05e618e95bb8c9bc8faea0029be54b8a91d81a360a6bcb00985f79a5979c1ca985c8e138b0a140264ce430df84a6b1051cf364cdf4eb01544bbd6c6f6ea40cb389edfd05f3850085718b6e75f455f01b7b72ee178168c0d67b8854e8b6689a402aa38f28159213381a8acae29c7540b7ede4f241fabc1628079b3c0e437737357faa5b7a74749f331efe0202ffe4b3dff730a311c4fe4b0655f21332913be677e9b32b13ac340fee73ea8cfc34e9f89bc22cb80386366b27a1bf580c24dcde6859fb7c833a7a8bec5511923adaf7b073a7711a14e94335792f46b7394742f488c604680ab3925a31b70eafdc797e8c8638656b0d00e78b2a977da5d973cbba3ed20540930dcf4bf3d97b4654fe6a76b2c1f8230f2833b60729a8ef682eef74e552be6e6f3b6d5f2a874158ced5e31ce5f6ed3a2bb25572b08054cce91203f83153357aac5ad9e3896cdacd90a2e65c0bd023e2aa336f98c1c5e39e200e2deabc50fc1a4fcc4639d1ab7f2d3daa163e0bcad26b7677a87e84015c9389f3ab237f8e8ccfb584675c93b5eb37af75cece089157f2df8203087eb6804a7427983d5a03639462c926d7041e5cff6ce3f4b1a75bbc4f0b76ee0f96ebb33371771f72154aefaf4da6f2dbd8118dfc3e2108e5d98d40ba80510a75c4e3d97d913c857ca98865ef23d9f80466862f6c043b0a05b126fd1dc19d9ebc120b24c4a2bd9b9ae2f3f6c9c95ac4c7ce415e6c09c7fec1980497f204f2c291d473cb4723d24d8a821d74ce3e9bffc52e3ce5f570d070e2408c70e023f634de8abdb9559149c7f625b4a1457236616ee97ac877731d0d03432d6d45ca3105dcbe47dffcf871175b815d6e99710c2c8897612d90bda04acafa8788e45c38c959340e09f6b316a4fd9f6383fbcae6b41352d5c9158fd2fcc91bf0c90eb79dcae10fea4f9ceb27f0f838bd083984452f5246d53ea27ebb188b5223af35ce951e6634863bd510ac4c06bc7e9a99d6d832a66fd08abbc02df94aa8fb27156b17cacb45eb7e2cd1b2b10ed43cb175f65c3d2b32548feaf017ae066667658b88946ab9ff168ca5da524264325374679ce0b3171c436106cbdc4a58f767e840a917e99dab1c0000",
        }
    )
    for txin in txins:
        tx = txs[txin.prev_hash]
        result = unblind(
            client=client,
            txo=tx.vout[txin.prev_index],
            rangeproof=tx.wit.vtxoutwit[txin.prev_index].rangeproof,
        )
        txin.confidential = proto.TxConfidentialAsset(
            asset=LBTC_ASSET,
            amount_blind=bytes(result.blinding_factor.data),
            asset_blind=bytes(result.asset_blinding_factor.data),
        )

    txouts = [
        proto.TxOutputType(
            address=get_confidential_address(client, "44'/1'/0'/0/1"),
            amount=1000_0000,
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
            amount=233_0000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=bytes.fromhex(
                    "0150f5adfc466b1a89077bf53259e4a1e0bbfe7812839df68d56d24f91ee65c3"
                ),
                asset_blind=b"\x44" * 32,
                nonce_privkey=b"\xBB" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address="",
            amount=1_0000,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        ),  # fee
    ]

    with client:
        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    tx = generate_proofs(client=client, tx=serialized_tx, txins=txins, txouts=txouts)
    assert (
        tx.serialize().hex()
        == "02000000010178e549c0998815817af9ab8b5aad7b976d58ce1a0031398ac2497b48b818319600000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1f0030000030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e81085409792c5b2a1cdf5259e13cf12288425963929b0502b939ceae0f300879f47ca7bf0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000271000000000000000000247304402200d0792947ea13f6f7aa703c3d8c9c8a0210df77993017c0fdcfc42be3abf07b2022003402a22550226e16cadd7258bae5858e3f3e090df8d34214b8b18f693e5efcf0150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac0043010001d5d33954cad50a1650ef62b2ac98f0cb451e252568002fcdded57d01966109ca0b5b112541e0504cca9a2f875423a00f6c520f1433f42cfad767a84403f234e7fd0c0a601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd347430100014c33ccf5a740051176d4a55dd3c30d537d3e29acb593457268034c0732fe9df1e61772d61d35c8101e6a8478bcb098fbb388791a92522ef6ca9b82608b79a70ffd0c0a601f0000000000000001f43d930100e11fa7b0dd515b60bd95fc27232ee1e4e632466955d891a9b58b333a340dc1f69b306ada953b3b2a3917899754f214c69bb757d855386df3bf8e8cef02e9a6186924d1b58be3ede20f7d422baf81b40ba788e3594c6c2b552681835f56c4a220d2ff8a7e7706765da67ebe2aafc77dbb3ad3fd0e9a3b64c3b7046f52d7a71ad4ef4f7ce34787a242e466e5b5fc3cbd5fb3287289d2d52c4462de884d6733fe4fd71a644ae3a45c6baa46faa049f3d753613dfb96e3e08e8a59e65a6a07a611bef9e69a8627957530476e1d78bf8c9d37322a89dd635dbbe8dfc4faf5302d199b76835fd0fe00c5b9b8ce9592def37dbe86792af77335c25092564f1b8be6f8093fbe01318a4d3f5b5776bcbcfe8748180c61f584dc9832cc03aaa0d6ed9369832c272bf348e00ce245aaceb1ef21f1bdba1b848719d1af283b5f82c41ecfdc2406097d305a126c9aa937b44917128dd36318892af9244077a1d93a6d6f86f63b6ce16c449ca2fe35d5f741b98117bc4872df48d665841b4e41475cc255ea9768925e89284f6d038413e95bdba2b47f01d042da1433858bed41e8d60fe2796c74ad5ec9792690c6950d362e29e213d00a50fc2baf973f0744ca280e54a69e99d028900163e34e31566866c9935cd679919e5b1a0d314b55d2ad173f8c63d95f6649fd7766b3ae24499badc09605b2802284f78600e9c42d04e698a62df75bac688373c7df1b82a4541d2e5fff0dd11da40b34fdde11eed1cd8adc24b77ae0135a8dd8e1ab31b13e4f1f23e21f15cdbdfd2b761ddfa438dadea6f6a731673a3cbe71aa201ff61dab49d079dc1f7da8c4254da4c5430e1e055685cedc4b290f4816c0671692d31918065fcd0ef8a99251f2912e5e45e94dfb7a72354588458e2fa652676e552227a11ded3db21f67604202515967e3bfb8192d0cf575e3b1ad1815c9c2581fbc609b66c9b487d3b5a60302af0fe5c45b68c7e17d70fcfa09e5fc8cb3a43dd8613faf0e665297be8f7e23ce516c10d7fce166e566995e58ac5a9d88560ce556abcee30f2c3fb29beccbd3b4ad1add090b190347e6711f15b597c5d04c84f9c9bfac507d2d84d743a716921725a7a8137a20283d47b9716118ea523ab57a8c85d457923a3c279d15bd027c2abd0b60ac1c3848b69b63710836fbac08414fc892b684e2b175751bccd57999fff05db7adecf1ef4de0b9bc641b9f65359368c045608288a4bb9892db5cd199871cdcbf3cdb4fca5704c33e25cd50814a41517376e1736fa85da8ecc71f5beb3632809c1947b460a8283423f2f535526cec6c74053f0aed9320494f7001a3eae791f2e4cdfd0197ab123e47738969b998a9d2bbc40256206fb274be2b338ab5ebedad7dc0fc37a0ce7061f3f7086c4a29c95b4b6028e1126029a9a9c9b2df57f15ecd99f67e853380d70d453e9e88a8101b10a46f8d0cd473d3bc0ff5ca036cb357ebe87b5259c9eb3e616913271e5bc1dd476b8358ef9ce88e555b67d80d479acf97b4bf4e7961ad42af06c60e467c3d95ff4c0e57f5a35a2bcd18ab5a54dafc9b9f441dea886fa8c1cabdf549dd90e76ba35e3ea2d4b93afb7a787f84b28b807134427ad77106fc52e127e756a6a9f563b158ea0355dc9d4b2ba597917a92ac552b8ac3c9b2f0ed3a5067fbb4e36874a2d0c4c94944714c4308b8545870ebdae6f0f72e4fe003d9cf99ac53cadc407575e595f389037e027dffe2c86e5030efde272f3be3594d0e27b44e8cafc330c13ab4982623cf7cad4802320f545f3662d1fe1d7dd14e55dcac53e4e160945c8fb6c06013a4198c0a9cdae31b636d2ee8a7bffed6bfb14f2c354be1a1748bc46395461840212d613155bfb0f4baf21d98e38d17b333a2e673d2db0f0df9f8de4b146bae8e8b40bcd80197d7a0733857d20fd2c0cb8b36ee90b75b2f8d1ea99194f90c2b4c469701d2ce64ac64936f8f8d30ff381fd5257ff4ec2a31e4fb25beffcb17736c461bd312f7bab744b8f1d4e6f454d4bfcbb3e76b50f4fea8007dadf0747918f7f5496da4734d28ca17d91c7bbb43ca7884101e4c85f56595567c804cf4715e195f9a19ddf85df51b416f170c0264934205851c786a4d4e1c182a00be6366045aa81ca1ba95476cbab25a918e8507ac6afc478a3b7cecba83d55089299750ec1135eb8551e1c8d7a15cf18181d3e54e70a06e53fc5a089f0b30267386227fc709dadf9e5b1bccd98e15a1fbe3d57d976442be1eb12e7b9c14fd8ed85ef5fa09ec293e337e7dd3ccb82a2a861b7cceeb759d9a2e372d126254de02c1322497c4e6dee486e90b923c643dc9817e65582cdcf8f7de4d6cc98d08753b0d9f49253a2308dac71b846089c1805eb48f24e2c6508f36cd11d8337d151c02c1869ef103af5b0d15c373a154fad714b299dd5ebb08258dec7745dbdfc405d41458f2cb7215740f7d1b04133ece63e8e54395506925f6681efb08c836d8c3112d1f1af3021024fd4f90eef2a0da3b232298e0820156f93695d54d5af47ce6aeabc4727a4305b6c07f7a1b66e13684fb5882faaab15387076d04a6e7640493c15443223c399aff38198fabd1fbdd0652ce69dadab9c201427050d4bfd0d27050b3893e7b1c873b9839343c077b616a97cfd09f97e45c4f7d114da01136579a226aa065f94b5bc2f3e1b8652ac3d4fadfc3a0e4f4571d1564567e58bc4778aa051c0e160fd1ab2a877c0848bc133648094f2fc6632b9fa1f7b9e5d3400424242adeee74b8ad4fa6aa486edd066df6b268ed30186c1da06971d952d6b3bfaa123479d74fbeca0c8bae9bfb3f9373d0d9aad0afa9a4392f0b4fe48b022fb50d7ffd8222c269733d4a7ba2fc7617249671f368c53ffec271b25ffc20643a5c91d01cd36f467aa8edd8ff5915dd9d9ef9bdc845fb0899e38e2ac08d80a92361efe62b067eaaff670cb767da616b929eaf27f2a75b9eecd89db70c71ff3990e847c24583ff3003ef1ea96cd6b7b21e4251b07680d893ff502efeb0b48dcaf61d50f581d502db912c4d6e8cd69aa105170b98da05c49b47d7a207cb84e9a137ecf31bb95a58b9a87d6000fb09ef288b66f0f5943d3c39ffe295e3676724396f7fd7fdcd1b8c5443ecfb3535bba2dc74c7d78a52a817704f584fcff4edca6fd5214e28d45c585537b92faf173b43d8655158799bb57666b1f5da75cfc57d0c7307b1560ae0f02d837622349726156ec4e963d758c5939827e51685d9fa1e264071117d129a5ccc0db5c029230186cefbcdbe39c048ae431f2df60eec1fe08323652d90ade596f64d78ba472efd25d106788f78821c2ca5f574b456dd1bf0e7bf4245049f316a9952d2e73f1c2d41cbac8478c7722ae4f6637ea5751ae9a20d4a0d24704768fac9f206bfb2d1d0d97f6bde99ae7de20b6d6eb07af77bf176925a1a04c0ce22b33968ae57ae546a92726d217e1ff23f345d0397a354a6593e7ed6582f245366a7fef864d8b6905577e1242234d3a8d680aeddb08153e575c5fefc09ec50904f2d7ac0122db73da9d9a685f5454c9ee55983c2e4a318b24213a38e2e2b62f56b347d070f84526f0a1e9bf492b30f0c8843ba299cbf151e4e6e43fd9dfb310000"
    )


# $ e1-cli getrawtransaction 83612e7360e0ff589f0f8ee9202c63f061f10672775abb58aa7ed8286860e469 1
# {
#   "txid": "83612e7360e0ff589f0f8ee9202c63f061f10672775abb58aa7ed8286860e469",
#   "hash": "b006d90aa82184da2b589791cb3bae9fa7c7c3f3e4dc707f54ef9fb0c2822021",
#   "wtxid": "b006d90aa82184da2b589791cb3bae9fa7c7c3f3e4dc707f54ef9fb0c2822021",
#   "withash": "82eadcf2b2d25f33c861369ed99a429befaa1a122ece1728b5baa07dbc1a9caf",
#   "version": 2,
#   "size": 5822,
#   "vsize": 1739,
#   "weight": 6953,
#   "locktime": 0,
#   "vin": [
#     {
#       "txid": "963118b8487b49c28a3931001ace586d977bad5a8babf97a81158899c049e578",
#       "vout": 0,
#       "scriptSig": {
#         "asm": "00207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1",
#         "hex": "2200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1"
#       },
#       "is_pegin": false,
#       "sequence": 1008,
#       "txinwitness": [
#         "304402200d0792947ea13f6f7aa703c3d8c9c8a0210df77993017c0fdcfc42be3abf07b2022003402a22550226e16cadd7258bae5858e3f3e090df8d34214b8b18f693e5efcf01",
#         "748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "09c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf",
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
#       "valuecommitment": "09792c5b2a1cdf5259e13cf12288425963929b0502b939ceae0f300879f47ca7bf",
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
#   "hex": "02000000010178e549c0998815817af9ab8b5aad7b976d58ce1a0031398ac2497b48b818319600000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1f0030000030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e81085409792c5b2a1cdf5259e13cf12288425963929b0502b939ceae0f300879f47ca7bf0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000271000000000000000000247304402200d0792947ea13f6f7aa703c3d8c9c8a0210df77993017c0fdcfc42be3abf07b2022003402a22550226e16cadd7258bae5858e3f3e090df8d34214b8b18f693e5efcf0150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac0043010001d5d33954cad50a1650ef62b2ac98f0cb451e252568002fcdded57d01966109ca0b5b112541e0504cca9a2f875423a00f6c520f1433f42cfad767a84403f234e7fd0c0a601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd347430100014c33ccf5a740051176d4a55dd3c30d537d3e29acb593457268034c0732fe9df1e61772d61d35c8101e6a8478bcb098fbb388791a92522ef6ca9b82608b79a70ffd0c0a601f0000000000000001f43d930100e11fa7b0dd515b60bd95fc27232ee1e4e632466955d891a9b58b333a340dc1f69b306ada953b3b2a3917899754f214c69bb757d855386df3bf8e8cef02e9a6186924d1b58be3ede20f7d422baf81b40ba788e3594c6c2b552681835f56c4a220d2ff8a7e7706765da67ebe2aafc77dbb3ad3fd0e9a3b64c3b7046f52d7a71ad4ef4f7ce34787a242e466e5b5fc3cbd5fb3287289d2d52c4462de884d6733fe4fd71a644ae3a45c6baa46faa049f3d753613dfb96e3e08e8a59e65a6a07a611bef9e69a8627957530476e1d78bf8c9d37322a89dd635dbbe8dfc4faf5302d199b76835fd0fe00c5b9b8ce9592def37dbe86792af77335c25092564f1b8be6f8093fbe01318a4d3f5b5776bcbcfe8748180c61f584dc9832cc03aaa0d6ed9369832c272bf348e00ce245aaceb1ef21f1bdba1b848719d1af283b5f82c41ecfdc2406097d305a126c9aa937b44917128dd36318892af9244077a1d93a6d6f86f63b6ce16c449ca2fe35d5f741b98117bc4872df48d665841b4e41475cc255ea9768925e89284f6d038413e95bdba2b47f01d042da1433858bed41e8d60fe2796c74ad5ec9792690c6950d362e29e213d00a50fc2baf973f0744ca280e54a69e99d028900163e34e31566866c9935cd679919e5b1a0d314b55d2ad173f8c63d95f6649fd7766b3ae24499badc09605b2802284f78600e9c42d04e698a62df75bac688373c7df1b82a4541d2e5fff0dd11da40b34fdde11eed1cd8adc24b77ae0135a8dd8e1ab31b13e4f1f23e21f15cdbdfd2b761ddfa438dadea6f6a731673a3cbe71aa201ff61dab49d079dc1f7da8c4254da4c5430e1e055685cedc4b290f4816c0671692d31918065fcd0ef8a99251f2912e5e45e94dfb7a72354588458e2fa652676e552227a11ded3db21f67604202515967e3bfb8192d0cf575e3b1ad1815c9c2581fbc609b66c9b487d3b5a60302af0fe5c45b68c7e17d70fcfa09e5fc8cb3a43dd8613faf0e665297be8f7e23ce516c10d7fce166e566995e58ac5a9d88560ce556abcee30f2c3fb29beccbd3b4ad1add090b190347e6711f15b597c5d04c84f9c9bfac507d2d84d743a716921725a7a8137a20283d47b9716118ea523ab57a8c85d457923a3c279d15bd027c2abd0b60ac1c3848b69b63710836fbac08414fc892b684e2b175751bccd57999fff05db7adecf1ef4de0b9bc641b9f65359368c045608288a4bb9892db5cd199871cdcbf3cdb4fca5704c33e25cd50814a41517376e1736fa85da8ecc71f5beb3632809c1947b460a8283423f2f535526cec6c74053f0aed9320494f7001a3eae791f2e4cdfd0197ab123e47738969b998a9d2bbc40256206fb274be2b338ab5ebedad7dc0fc37a0ce7061f3f7086c4a29c95b4b6028e1126029a9a9c9b2df57f15ecd99f67e853380d70d453e9e88a8101b10a46f8d0cd473d3bc0ff5ca036cb357ebe87b5259c9eb3e616913271e5bc1dd476b8358ef9ce88e555b67d80d479acf97b4bf4e7961ad42af06c60e467c3d95ff4c0e57f5a35a2bcd18ab5a54dafc9b9f441dea886fa8c1cabdf549dd90e76ba35e3ea2d4b93afb7a787f84b28b807134427ad77106fc52e127e756a6a9f563b158ea0355dc9d4b2ba597917a92ac552b8ac3c9b2f0ed3a5067fbb4e36874a2d0c4c94944714c4308b8545870ebdae6f0f72e4fe003d9cf99ac53cadc407575e595f389037e027dffe2c86e5030efde272f3be3594d0e27b44e8cafc330c13ab4982623cf7cad4802320f545f3662d1fe1d7dd14e55dcac53e4e160945c8fb6c06013a4198c0a9cdae31b636d2ee8a7bffed6bfb14f2c354be1a1748bc46395461840212d613155bfb0f4baf21d98e38d17b333a2e673d2db0f0df9f8de4b146bae8e8b40bcd80197d7a0733857d20fd2c0cb8b36ee90b75b2f8d1ea99194f90c2b4c469701d2ce64ac64936f8f8d30ff381fd5257ff4ec2a31e4fb25beffcb17736c461bd312f7bab744b8f1d4e6f454d4bfcbb3e76b50f4fea8007dadf0747918f7f5496da4734d28ca17d91c7bbb43ca7884101e4c85f56595567c804cf4715e195f9a19ddf85df51b416f170c0264934205851c786a4d4e1c182a00be6366045aa81ca1ba95476cbab25a918e8507ac6afc478a3b7cecba83d55089299750ec1135eb8551e1c8d7a15cf18181d3e54e70a06e53fc5a089f0b30267386227fc709dadf9e5b1bccd98e15a1fbe3d57d976442be1eb12e7b9c14fd8ed85ef5fa09ec293e337e7dd3ccb82a2a861b7cceeb759d9a2e372d126254de02c1322497c4e6dee486e90b923c643dc9817e65582cdcf8f7de4d6cc98d08753b0d9f49253a2308dac71b846089c1805eb48f24e2c6508f36cd11d8337d151c02c1869ef103af5b0d15c373a154fad714b299dd5ebb08258dec7745dbdfc405d41458f2cb7215740f7d1b04133ece63e8e54395506925f6681efb08c836d8c3112d1f1af3021024fd4f90eef2a0da3b232298e0820156f93695d54d5af47ce6aeabc4727a4305b6c07f7a1b66e13684fb5882faaab15387076d04a6e7640493c15443223c399aff38198fabd1fbdd0652ce69dadab9c201427050d4bfd0d27050b3893e7b1c873b9839343c077b616a97cfd09f97e45c4f7d114da01136579a226aa065f94b5bc2f3e1b8652ac3d4fadfc3a0e4f4571d1564567e58bc4778aa051c0e160fd1ab2a877c0848bc133648094f2fc6632b9fa1f7b9e5d3400424242adeee74b8ad4fa6aa486edd066df6b268ed30186c1da06971d952d6b3bfaa123479d74fbeca0c8bae9bfb3f9373d0d9aad0afa9a4392f0b4fe48b022fb50d7ffd8222c269733d4a7ba2fc7617249671f368c53ffec271b25ffc20643a5c91d01cd36f467aa8edd8ff5915dd9d9ef9bdc845fb0899e38e2ac08d80a92361efe62b067eaaff670cb767da616b929eaf27f2a75b9eecd89db70c71ff3990e847c24583ff3003ef1ea96cd6b7b21e4251b07680d893ff502efeb0b48dcaf61d50f581d502db912c4d6e8cd69aa105170b98da05c49b47d7a207cb84e9a137ecf31bb95a58b9a87d6000fb09ef288b66f0f5943d3c39ffe295e3676724396f7fd7fdcd1b8c5443ecfb3535bba2dc74c7d78a52a817704f584fcff4edca6fd5214e28d45c585537b92faf173b43d8655158799bb57666b1f5da75cfc57d0c7307b1560ae0f02d837622349726156ec4e963d758c5939827e51685d9fa1e264071117d129a5ccc0db5c029230186cefbcdbe39c048ae431f2df60eec1fe08323652d90ade596f64d78ba472efd25d106788f78821c2ca5f574b456dd1bf0e7bf4245049f316a9952d2e73f1c2d41cbac8478c7722ae4f6637ea5751ae9a20d4a0d24704768fac9f206bfb2d1d0d97f6bde99ae7de20b6d6eb07af77bf176925a1a04c0ce22b33968ae57ae546a92726d217e1ff23f345d0397a354a6593e7ed6582f245366a7fef864d8b6905577e1242234d3a8d680aeddb08153e575c5fefc09ec50904f2d7ac0122db73da9d9a685f5454c9ee55983c2e4a318b24213a38e2e2b62f56b347d070f84526f0a1e9bf492b30f0c8843ba299cbf151e4e6e43fd9dfb310000",
#   "blockhash": "e09b6b98c547a489a376a74f7b3b9bf75dc06224006ed5b56276ad0ca14c13db",
#   "confirmations": 1,
#   "time": 1579342185,
#   "blocktime": 1579342185,
#   "ToString": "CTransaction(hash=83612e7360, ver=2, vin.size=1, vout.size=3, nLockTime=0)\n    CTxIn(COutPoint(963118b848, 0), scriptSig=2200207b6de8dfee7092963c, nSequence=1008)\n    CScriptWitness(304402200d0792947ea13f6f7aa703c3d8c9c8a0210df77993017c0fdcfc42be3abf07b2022003402a22550226e16cadd7258bae5858e3f3e090df8d34214b8b18f693e5efcf01, 748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a91434fbecbc9786f628943d2abf87)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a9140de6434adf2f3912732cdc20db)\n    CTxOut(nAsset=b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23, nValue=0.00010000, scriptPubKey=)\n    010001d5d33954cad50a1650ef62b2ac98f0cb451e252568002fcdded57d01966109ca0b5b112541e0504cca9a2f875423a00f6c520f1433f42cfad767a84403f234e7\n    601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd347\n    0100014c33ccf5a740051176d4a55dd3c30d537d3e29acb593457268034c0732fe9df1e61772d61d35c8101e6a8478bcb098fbb388791a92522ef6ca9b82608b79a70f\n    601f0000000000000001f43d930100e11fa7b0dd515b60bd95fc27232ee1e4e632466955d891a9b58b333a340dc1f69b306ada953b3b2a3917899754f214c69bb757d855386df3bf8e8cef02e9a6186924d1b58be3ede20f7d422baf81b40ba788e3594c6c2b552681835f56c4a220d2ff8a7e7706765da67ebe2aafc77dbb3ad3fd0e9a3b64c3b7046f52d7a71ad4ef4f7ce34787a242e466e5b5fc3cbd5fb3287289d2d52c4462de884d6733fe4fd71a644ae3a45c6baa46faa049f3d753613dfb96e3e08e8a59e65a6a07a611bef9e69a8627957530476e1d78bf8c9d37322a89dd635dbbe8dfc4faf5302d199b76835fd0fe00c5b9b8ce9592def37dbe86792af77335c25092564f1b8be6f8093fbe01318a4d3f5b5776bcbcfe8748180c61f584dc9832cc03aaa0d6ed9369832c272bf348e00ce245aaceb1ef21f1bdba1b848719d1af283b5f82c41ecfdc2406097d305a126c9aa937b44917128dd36318892af9244077a1d93a6d6f86f63b6ce16c449ca2fe35d5f741b98117bc4872df48d665841b4e41475cc255ea9768925e89284f6d038413e95bdba2b47f01d042da1433858bed41e8d60fe2796c74ad5ec9792690c6950d362e29e213d00a50fc2baf973f0744ca280e54a69e99d028900163e34e31566866c9935cd679919e5b1a0d314b55d2ad173f8c63d95f6649fd7766b3ae24499badc09605b2802284f78600e9c42d04e698a62df75bac688373c7df1b82a4541d2e5fff0dd11da40b34fdde11eed1cd8adc24b77ae0135a8dd8e1ab31b13e4f1f23e21f15cdbdfd2b761ddfa438dadea6f6a731673a3cbe71aa201ff61dab49d079dc1f7da8c4254da4c5430e1e055685cedc4b290f4816c0671692d31918065fcd0ef8a99251f2912e5e45e94dfb7a72354588458e2fa652676e552227a11ded3db21f67604202515967e3bfb8192d0cf575e3b1ad1815c9c2581fbc609b66c9b487d3b5a60302af0fe5c45b68c7e17d70fcfa09e5fc8cb3a43dd8613faf0e665297be8f7e23ce516c10d7fce166e566995e58ac5a9d88560ce556abcee30f2c3fb29beccbd3b4ad1add090b190347e6711f15b597c5d04c84f9c9bfac507d2d84d743a716921725a7a8137a20283d47b9716118ea523ab57a8c85d457923a3c279d15bd027c2abd0b60ac1c3848b69b63710836fbac08414fc892b684e2b175751bccd57999fff05db7adecf1ef4de0b9bc641b9f65359368c045608288a4bb9892db5cd199871cdcbf3cdb4fca5704c33e25cd50814a41517376e1736fa85da8ecc71f5beb3632809c1947b460a8283423f2f535526cec6c74053f0aed9320494f7001a3eae791f2e4cdfd0197ab123e47738969b998a9d2bbc40256206fb274be2b338ab5ebedad7dc0fc37a0ce7061f3f7086c4a29c95b4b6028e1126029a9a9c9b2df57f15ecd99f67e853380d70d453e9e88a8101b10a46f8d0cd473d3bc0ff5ca036cb357ebe87b5259c9eb3e616913271e5bc1dd476b8358ef9ce88e555b67d80d479acf97b4bf4e7961ad42af06c60e467c3d95ff4c0e57f5a35a2bcd18ab5a54dafc9b9f441dea886fa8c1cabdf549dd90e76ba35e3ea2d4b93afb7a787f84b28b807134427ad77106fc52e127e756a6a9f563b158ea0355dc9d4b2ba597917a92ac552b8ac3c9b2f0ed3a5067fbb4e36874a2d0c4c94944714c4308b8545870ebdae6f0f72e4fe003d9cf99ac53cadc407575e595f389037e027dffe2c86e5030efde272f3be3594d0e27b44e8cafc330c13ab4982623cf7cad4802320f545f3662d1fe1d7dd14e55dcac53e4e160945c8fb6c06013a4198c0a9cdae31b636d2ee8a7bffed6bfb14f2c354be1a1748bc46395461840212d613155bfb0f4baf21d98e38d17b333a2e673d2db0f0df9f8de4b146bae8e8b40bcd80197d7a0733857d20fd2c0cb8b36ee90b75b2f8d1ea99194f90c2b4c469701d2ce64ac64936f8f8d30ff381fd5257ff4ec2a31e4fb25beffcb17736c461bd312f7bab744b8f1d4e6f454d4bfcbb3e76b50f4fea8007dadf0747918f7f5496da4734d28ca17d91c7bbb43ca7884101e4c85f56595567c804cf4715e195f9a19ddf85df51b416f170c0264934205851c786a4d4e1c182a00be6366045aa81ca1ba95476cbab25a918e8507ac6afc478a3b7cecba83d55089299750ec1135eb8551e1c8d7a15cf18181d3e54e70a06e53fc5a089f0b30267386227fc709dadf9e5b1bccd98e15a1fbe3d57d976442be1eb12e7b9c14fd8ed85ef5fa09ec293e337e7dd3ccb82a2a861b7cceeb759d9a2e372d126254de02c1322497c4e6dee486e90b923c643dc9817e65582cdcf8f7de4d6cc98d08753b0d9f49253a2308dac71b846089c1805eb48f24e2c6508f36cd11d8337d151c02c1869ef103af5b0d15c373a154fad714b299dd5ebb08258dec7745dbdfc405d41458f2cb7215740f7d1b04133ece63e8e54395506925f6681efb08c836d8c3112d1f1af3021024fd4f90eef2a0da3b232298e0820156f93695d54d5af47ce6aeabc4727a4305b6c07f7a1b66e13684fb5882faaab15387076d04a6e7640493c15443223c399aff38198fabd1fbdd0652ce69dadab9c201427050d4bfd0d27050b3893e7b1c873b9839343c077b616a97cfd09f97e45c4f7d114da01136579a226aa065f94b5bc2f3e1b8652ac3d4fadfc3a0e4f4571d1564567e58bc4778aa051c0e160fd1ab2a877c0848bc133648094f2fc6632b9fa1f7b9e5d3400424242adeee74b8ad4fa6aa486edd066df6b268ed30186c1da06971d952d6b3bfaa123479d74fbeca0c8bae9bfb3f9373d0d9aad0afa9a4392f0b4fe48b022fb50d7ffd8222c269733d4a7ba2fc7617249671f368c53ffec271b25ffc20643a5c91d01cd36f467aa8edd8ff5915dd9d9ef9bdc845fb0899e38e2ac08d80a92361efe62b067eaaff670cb767da616b929eaf27f2a75b9eecd89db70c71ff3990e847c24583ff3003ef1ea96cd6b7b21e4251b07680d893ff502efeb0b48dcaf61d50f581d502db912c4d6e8cd69aa105170b98da05c49b47d7a207cb84e9a137ecf31bb95a58b9a87d6000fb09ef288b66f0f5943d3c39ffe295e3676724396f7fd7fdcd1b8c5443ecfb3535bba2dc74c7d78a52a817704f584fcff4edca6fd5214e28d45c585537b92faf173b43d8655158799bb57666b1f5da75cfc57d0c7307b1560ae0f02d837622349726156ec4e963d758c5939827e51685d9fa1e264071117d129a5ccc0db5c029230186cefbcdbe39c048ae431f2df60eec1fe08323652d90ade596f64d78ba472efd25d106788f78821c2ca5f574b456dd1bf0e7bf4245049f316a9952d2e73f1c2d41cbac8478c7722ae4f6637ea5751ae9a20d4a0d24704768fac9f206bfb2d1d0d97f6bde99ae7de20b6d6eb07af77bf176925a1a04c0ce22b33968ae57ae546a92726d217e1ff23f345d0397a354a6593e7ed6582f245366a7fef864d8b6905577e1242234d3a8d680aeddb08153e575c5fefc09ec50904f2d7ac0122db73da9d9a685f5454c9ee55983c2e4a318b24213a38e2e2b62f56b347d070f84526f0a1e9bf492b30f0c8843ba299cbf151e4e6e43fd9dfb31\n    \n    \n"
# }


@pytest.mark.altcoin
@pytest.mark.setup_client(mnemonic=MNEMONIC_ALLALLALL)
def test_send_elements_multisig_csv_2_confidential(client):
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
                confidential=True,
            )
            == "AzpwvcT8N3V4GDY6iMejsUrZ6ZMLRFh4sj3fywQmF1NwWX2yJyFnmkRYkEBwYs3JK6UybmJzj5Py5aU6"  # XaEtEibtM5uecf62yVpXiFMVhCkuGdkKAG
        )

    txins = [
        proto.TxInputType(
            address_n=parse_path("49'/1'/1'/0/1"),
            prev_hash=bytes.fromhex(
                "df049837bc507bad44bac846bff813bdecdc577a419b2f3f46c3326af2395469"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=1234_0000,
            sequence=None,  # MUST BE UNSET!
        )
    ]

    txs = txs_from_hex(
        {
            "df049837bc507bad44bac846bff813bdecdc577a419b2f3f46c3326af2395469": "0200000001010e7f7a807ea94a1510b65815f2d21c06c47f8bf09af89e1fb3b1e34c24fa5a380000000017160014c35999a66c1a90ee07b098d9f1e56f34707c3332fdffffff030aa057e6ec5261eb7733085b1b16e73c93ec077d23773df47d31848d6271ade79909bd9f0e71e58ce2ad0b866311a5c77a004bb3b92c6baacede95c3efddc9854aeb0296f192052b39c785a453481aba5822d82f33fda5f78a6d7c77ae0ff4808fb8a617a91436fa3cc5b6333c6310f201e3f8327877b2712f84870a89b9c8330716a963054596d1caeda15a6dee17296b5bd0a466d1928bf3e5dbad099b09793f89a1221369d868e599ed0da27c07ef00e5faf50b63a3e1bfc2c2a59e03be6cb9daf3367ec0db8d57818650bcbfd13cfa8e93c213fafb14289954a1efa117a914fb1731356772ce6c36b525d7989092c21e385bab8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000927c00000800000000000247304402201b147dd30179f08c251a26a674211a03ac49b3ec901fe5eeb4fae34c38376c4802207598c6b7959921fcb3de1e3d93dc84aa5cfacdbd6a2b1cfc13a07414db6351c30121024c660a06e6958b56627ff3653a5e82858ce951556c7083469d9f0c394abc61630043010001c86bc0cb17b8982dc6432736f1590fc3a27540b560b4aa3a628b0883f67c1e928e7faa0ef586df63267be5664cafad4889c503a888672ae145a792113639895afd4d0b60230000000000000001d1080053243bca0187e759d961a89fd2eb38f9e02204cadfe0a9313a2e63b2a373b59047777c74733cad7436f7498316c65c0654033aa83350486a90ea8817888d7f360e4c81b16027521d37825dc54095dd7658f32e526bd69c1cc65ac00625b56a57d03369bd97afe47cf90c71c6c6e809f1d6f159a992889b07e42557971f8dd67e3498e0727999908ac0409e88e0a256ca7992e53df31f18bdd1bef462a743f6f78f69eda5a1c173ea0b8c5fc2a7456f792fad2dfe8b6457d081c5b76fbeb05f459fca37b7eaa0922a8ade8265bea4ee43fae7260819fb728015d5ec3d0676e5bc69e9f2d25fadf86805f56c0b921bec9e813eb5dc6779bd9b356dc0a470bf926cb969c778427d634f42ddbc024b28fd5a4b433f8ddd01aba518cabcc654e4710c5c4c7045df8c71cdde0b3dd628b7a2a531e6786ef43e1356d3bfc7faf5ccb64cc2f9ee9f1b38b15086ef6b2ef1dac80b9e17cc5c110f955786400516a0c7234077d21c6fc7ffcc7506b6f2dd2a37a8c453ebd8bf914de543ec00fb3bca82b9ca7ccfb7a18251b9851abc4ae13ca62c62ad2f772c62b19ec4bb8d2afa297257616871c35476addf15c514f63d53e82e1bbee431ba1e5434f28b367caefa9b95450812c4f1a2d601ea64a49956fbd1200b862e4e28d8d883f4c4bbf80b2f8453db8b1861620351b2349965964b8864c5b63408110902a64c4f855adafd8d62bbbc437be02f52a731530b5281da4a02a2688350d38cd9f75aea39eaa113212b5d7de3abbd2223084087846114e6bcb016df1dc2ecea0c89d72e8c9904f81ea66876b4c2fb8e433216501fa93bf927cc01367d77642ead853bd9cf5cf21c129760262a80e28c47241c3290f398967d1484974174a21409d83230fddaa1ef0d2dee11b2ea200f5ea6c7c1317bd0b46f18cd0d03d2179c2c85f371e1dc07fb7008ce1e174e6afb12b6f5539340cc24d3f2e68c34db6c7f7d510a84a09c96e18808bc65085cc2428087365183e86ce39072fb2f930cc5456795edf8336deddfe04906349b903ed20a0d5c240803a88a7b503e46481eac113e86d5ba688a3ce6b771540986ddee28f189269bbbd96cbfd9b34780765c113e875d05c827dee23f8c5e0b8caeb0365df9bc31dc00aa399b036a257c7f2ca9c01bae65d74dfd84f5e3f5670a06956f63bd01ea3fdf1340173b19de7d00b50f44c68c3cd7bef93071bf74d151587610bd1a7545cdf307fdeaaeee11e5df5d819ae2d03078672a54d9b81c1e2cd76c2fe141b0106ec44b1f65fb3d70c9bc48bc35f9a81a0682cf9b7079cffb657e9d9b02c6b63763b5acb3dfdb4232185b01fe3c462d354b824ffc55a307e38545ba560f20fe96ed7b1a3941035e61fbfe8d075389a31176790181a674c86814f6772a166a9e559d98c7403d22318bbe39858000ac245605f8df9b728f47d934370ad613cec3fc6a4a799b62e3104852badec09de59c61f5edb44a7e4d96ba110470bd3c451cb0b3ab066e53122114acb352215a38d638e76b81d41d19e0074eea8aa9957083da3ffcf5203c7b4bd42f95a8857afae5e0053dac5b90d9a9e16ab4ef78374beccfd2bfd8881bf57c8dc04348b6d2b79636b2a497d38ee2249997b8b5b1414678f48de66508c4407c740a02d8485356e2f4362369e7002e1d054db34f347255ac2d0fa6b7a9ae2f24ba07c3e8615da4eab935efc7b51a2030b7b18e854eb9e5b1316b6ca76218d3419a5b3b0f5d2ab4af332e37abc088cd499e753eaf15bc6b36ac1e626d6e336e59d911ac3d544049a1280a26d5d880cf8223cb11b951eace5fc9f94f0a02cf0eddfeb17faab724885c6f01855bf75e0accd35284b0e92af94e468220f18436927dabdd57af064b3e60f835fa7e8763b359e5e4c1dc8f4bc733d87078f0e4e910739593e33edeecc3e31927498568175c756c00f7ce068ffcd6654240f0a9884a7d1d1a9644de3d26feb4ca207b875988a6058c8fa45af7f81fe83117e2aee654885bd2abe997defa6a6a78f16d5be450f7e03cd2128d65d73a3a6ff69422bf1d4db524e0c415dd1d36468a5cdc21a7adc664ea9e2690ba612e0d9256beda0cda4fa4958813cfeadbb4afa48335077fea7788dfbd0fb364c3ed51e2aef7f407e7f1e501d0b03710f711e9e7a859700f9726121785f46f3e434517641c8aca25d1b9b19f6b9dd05ab50fc979d2d3d497cc450683db6a4c65beffc5c345d3bf50feef3bf0146868465812a7d687a412a82dbc600cd84b0f08d2520d40419f2ecdeca65e679ee95a0b1317be7b1dcb27d16c970f0d52833c41357122d2d59349bdcac9b3d99cd657da09c4a2d25f969d1c52df1c17c8aae2917fe29293c3b56bd21a8f37ac489e27cf7a9af5803d682500fc20c38dd38aca274f1aa080501c33009d5f72d8e1f9bdb3526b958b3aead9ccbdcbdac71d56fea2e47a17e918240dfb81f8d56b38f299c7fda250e21a72038b4aa984b1b1ab9430c2de0b9a268ab05f3d1ba6509046774ee5fb3b301048cd8c1e7a948f37b9b7a07335a58162c988c5f9bc61b10b63a8e5b92ca0102e8640a837208506896d8ab18dbb678337bf20b9ee01254d4340853e7c358cd101cae0f8f6a0446b8afda9ff8c9666362247b50fc7bac9227caee30bc8ab63b83b54f51fbde8ba90ef0660114127cfa6de9dcc5c68817be86cd5f38d4376a6313cf5f98320cd8fcd617b127b7dbb4af9193f84a49f9a05dba78a42b353fcece5e8cee1b432c1ef4e9b5bb0be73d65df7f9a2a4f7f583ca969d4578cf6d82d0c4589107efcd7bd3d7366b051e5c102aa4198e26d7b2829b0689830e6cf4725a56c9e1bbedd5c57e14cd053d3b334644e9bab471d7ec7db6ff8c9449da073d0a187094959526f13eb364a24da7e2c89730cdc0bf2f1beb8ad96f73c478023b97b4e0474393194bf645d57b6dabf28584b93ca889ee9e8858447c9e6ed52040613bbbb6bfa3aadca9518ad8dc0f9c33710512bb7c3d50ac10c60e3ec40fe2a0f171a2b0dc8cd3ab70f678bc842d28501d0fc584551916ef92ea66bb17ffce4f187f2068d1aa181c5a3846f8f1a439a7cc6c8828dea07735dc3584b56bfe52e30899466e019ba30c6c4133c6ffa8e8d836afa1a3660eb6c896e4d261053c1bb02bcd4e6cd9397eb4edb5257d369f7fd92b91bc26b19d018705494b9c293d8c9cf0169fdd1a7914559396c12437e4b11131102e680358aa52b459f9ec6aa6796ead8173fecc390345cc9dc0cbcc486917c59608aa842151e9ebedd1645c4268ac69266e36ced5ac481d9ae7e6fe381d2d0a5facc68341f4d654e75146d59606f8d8936e214f561fe2fe8b09a6f9a5860096cfe580779ffce5e971b24083f399dd294b0e97721fbdd6ace3eab1500396ebd3d4f33cf199c59a0262a80c9a0d1ae3899d696fd7a7f8bc561d9f91e2df78492266a4c9e76e1ce0d0942ee4d5080b384acd1cf154118ccc7ed1ee69ecc85effdd62ec15bd7a6b19c7168470192b1a742b2b7cdf7a95acb0082beb23462e603b1efdc60b5ab763862eeea5e9dc553a60fbc0ea56edcaca5c56eb55a1d46e28e462a4b3cd46eb62bcf25de42687a48e336cc1f209c7db276e3d4ee34f2ea2b272025eabcff00eaad28f09e67162d7dfcbdcc8c16a324171cb5ba0e78597c060d0d5861ed98097b5d40a0d1507d6f92126cea79a148c81baf9b9fb064ed15db213ca02cdd6adfe68fb838eafbc5a67e71d3e5e671b11c38dc8e9d9fe7fe5245ec22bed5c3d1c0644a7773465f767fbc1138f90abf1a5f08c176bf6742d0cac1d242bff3f4a2a880d78063f89b64caaa226a43847ea52146b91f56f0bf509e4080483388d95cff15a8f33105fbf8d4a78d527ed0ec0975aac84ba3d0d3a6fe4d6193ae9148cf283c7e673e37c8d0b3c81e4dca54de744ab6167e065235307b14dbe23eac756a3c2871dac3baaf9de269cc3122f74d913639fe15f6a158e2439be08274cc262fbb24f0ea5bbb7f97ecf4e5925d3604af210c416e6e632532a624e3dbcee31fb77078ee3e310f152efaf513eade7a98c815481228d94430100013d59682abb0cb8b82b73402487147b372834253aa500ecface147c7b994938a4e7cb66e09df4cae1fb564704c4d08beb0acca3f27aa6cf396f8a66a7f5399628fd4d0b602300000000000000013d6000fe3b751c96d3781ae971ab43f1dd4528f2253d0bc9c0f6350978b9732cc6912e96804c96b242a8dc58a99e99e8a6e4c01b14d2cb7ff7198a14d3310e0c862b9c0d5473db4b6566bd2a25758851e133c5b840f339d4e5464098de8ff028265b165ef792d9cbb7663d1d8e85739a23fb5fcf1ffc33405f11aec64c12fece1f91423f24f66fec11e3b390bf0f15d86c7e1611238da76d1450de3dc2526721d899a706c039bfa8415fa33afb7fb609d382e8d90b5d933258a394dc6e3548041bdeee948035991d269e52570e13b7f343546fdc05cef78ce0afac76f8977eb012a827e2365421b592a773b4be1b0595a90a1a35dd213d56259ba7b10a7dd8b54936a667224e9e4ad659fab546b4c244992622e456c231df64a602929b803ab197fa46247e217e130291ba520bfd7503412c1794c0eefe7fcc6d750ea187171e240f775b04c703544b5470f3980d5508a319309ec893dc0e37c7dbfe23d2455c9b2c5f1387ca8fc5ce9e7b6b2ae9143f2fccc7b044755b1dd31177739aecfc096284f2c190bf27aebe9e607d87c83beba1b2003011369937451ee16b370cefc0a1ed08a50fa320fa5cecc4d718b3e2c434c9ff6e745041db90aabe625d3ebe364017c41ad3af3a7617a74317dc978d2c535edd8079a9edf61d02dd777df146642b48d74e19be443e78c400b0b99439a5fad1e77c58828907731a9cebbcf8288d58fe2ecdfdf30b4d42136b5eed2e4c50f964838992900a03519cf76b3e8ade65db91623022925f2616e60bfe63682a3cd71ff4cfb829e4e473eecd62e2c7807a85dd755c31c8180b8a0a55991b74f51c2b683f9f89bea826e95ac18008e692514018b23bb3127946e01f4e27c89445b58c752ef3615b2fee662a447f472b4c1fcc1aaccb79aa15e32cc436178c7dda9578c21b82085205fb15684920e49f64953dfbbce97831010a2df3d058f9a1c60caa8be7c7bff75e15f814a912460a752342f257eb5bdee37240044248d80ae2e1094e81abcb6b146732e4240b13cf9414ad24aa004956b0fca97d5f318ca093023938d2004dcee3b1bffed2f39b2409ae4960f9c6799346d8638d0ecf1c5b377626869bfd96e9a7caa4cbb2fa5a33c648f9abd94552905aef8dd954d90031bffa8637cef17cb341b5f4be33f69c606235dcb2bf5c87f9e66dbd67ea85a764541c080e80c3d94775854fc8e374b969e73e27d5d3e10f6c29c88227b0fef05b5b6353983631bbb84a44f43f7dfe5d81c5d17b15dd6379ed009ca283a51f9e372edf18ba1c2e137e84664c0f7ac13bcfb2ef93d489927cfbcb71597b62138235f324f21c1d8206fbc4772f50c2daf55a27aef0ee24544ccd30ba03bac946d91a489144fb51684f63126f196de8dab179fc9842d20949e0a815097438fc8ca5369803ead397b3c0045b944b991009a55d4308f485d6e83f8e7fff94079cffe120e3eaae9cfceb901a801502da80cd3b508a18733abd4956d7b2a65e32c77dae3fe73608998e1e486e2347912034bdf695e2abf06299d2f7efcea5b2396af35aa8660a7baba43e0baafe7d33cd342720d39b2e56e0b8185db2954e7f1e79dad32d74e88f17be573c29c96cc7e9d4898cf54da432d150806a8a00819d2ed1eff750e9fac1a1a698c656d9541a7922e96dd9d0e1ecb2b2119f3f6db4a14c75cad73e14c95fa05c8811c473565bbd41254b94b9408ee4010aad2883a7e1afd4d61df0c463bf7ac53103d4d1554379d6e949ab5bf6a78f6922693444e2f5db629ada8a4df56350bf938e6f271ad0231e68cf92e4917255ce8cbc424da61cc4d9210edff9f692efffba0537c89c71c732e040989cbb3e0953d3630ebfc15c4325cc72a8e423ecf2a4601bf3a71dd380a78e074d9a86abecdc8aefbd7bcbdde17c5dd50060c3866380122d931ce45fd1859b041aa82ecc2d23c91825e50b128bd17ad04be0fb9d5ce93ca45fada48515f00996be1046df053eee9bdf7ae6ac93b221a6d8a55817addab03af8414a39aba543b7a28fc188acf1589547732dae6ff06dd265e1cf2a1e167128be9f5a3dd43f235ec8170024aaf1639329f21e6ff1910c5a1431f3deaddd29749a043a68e9bb1be95f47d0ce4415bbb6ed139a984668e95c61ec0ae302914b7c159e040d0193fe723a5b7628e5920ff28c43a6757e9be73ebd6570a9005e9e3346a29c50792d7339154a22d27a5b8918649ed7b1bd1d6875cfbe933c1f8b58240c5c141fda9fa66d9a97ac999267f1817e1d17b7dd8f3fd007ffbe1dd083f14b5337402493e6b178f5b27df9709e33927091e5c3ca67666019edb779859c51ed2f440e3ad8ba8196da17808449f4b7d2b78a749b7f95858beba4d27b6682c1092c15e641c9f92562ebc6cb9f7cc871016dc01d92ba14a48b85330393487717b10df32eff7502fd63e80ff40ea5573aeea7504961efe0f5a7319fd7a0b1a320ab5ada8fd14d6dcad6bf55e871e774dd4d59f44cc99cae90c8d23927603281f15253cd158426d31ab78d33bb3af68dcd3f97e46aa761e85a7f1f1d1669ee9807c3de619b9b758ca9bb90bf52ea987de1c37559b6ecd10edaa636f660ded6868d026204b5604a2cf4210aa22f10b9120aedb14726ae0b03dc4a8c1dd2cf26516c7ba8455e69e587f4c9f6c91682448a42fa864bb27adfec1352dd2f6a2f5c77497032d75f63dc57b70679558156b6b77390af65c7518e5339c6187f0363cde87fa69a8997e956caa634eb7619c04e50194dd5a690537a59c88d4b572416cdbbfb86d32d9fec173371cc817ad5ee6bde8ee9fb84dc80300b795214d61257b6584b4acecf1e4b30fa25e4a59a75c1af4f56bd05c48bdb62d2a2a565421d81825137968a73803d01e3149458429bb665f2c2f4657b8aba204e2b2324b05f8cdbed2f7aa130316f3c8cf4ecf7f931f369a954f20e0559a2240cd5868873bba63ae1a3e93d6b9a294655c757cea84c4aa38a7804bfc6a11ba29b5a508cacdad32d78ddfd5922c60a464ee7ca176fbda7a0647b04c778c0a058c30124c0765d16ae307b8035b43c27ee43c863b292feb1f4f06a7e9ca36d557fa058bc2820dce079520462b18ee71f05844c4c46fdd842c0f5f611eb2c4009977f3e91e075ad35e12c732e56ce254b91562da55a9e369136a2de6d79fb36e83abeb07b651ea84649658dce588813478217d795857d9ab4ca6cf9ab7a939db942570425e9a0bb2dd10203325a2418fd113a4d474247614de9c39abdb2f459727664e8878dfdc549e1c5ebd7c32b38a7cf940bcc1526ba7c0fbc7303944a51f0340bc3413e541b1db7b79cc62bcdeb9be24fe166dd655d13baa02d8cf6ce2b8c7ced81e2edb00e08585dd889896bb562c11fb1f50ecdd5c56f09ecace2532fb4dc10add515587044411b92a7615a4e74f8f020317219496fa482eb0b6110b28cd97c8a0da91c01159288b6ee2463ae68bdfc4212f275238c361c007b9233bce89bf1186c03c65f95f117ddcad258057ad91167b18b8be0a90633207fa930693eb79003944ac797faf603a5ec223b37da534628f19530a3f46a3a4a4d620d01b51f4c7965442037cb8fdb00a362291fd0e37be84ed9da075cc855761ec20004c6c1b7e04ceada793de97e4e152d30b967e95d8e0f5f5a13b297ed8927b288972fd44e4a96b0db4e71dddc0c042990d13050adb1087a0b3f5127ba0e5822f50cb04ba2257c6de3760877f46ab494b43041f23f95a9fc14649b5ef0c044b3a5a55a5fe603f08f6bd65a3357f2ea4dc2745c84e10ff45fae00eae095507e769f1e0821a0a58ba51961ef56bf9be0b2e90fec38061c7bcd2df57de290c8d0635996597e9966eb83f2ebf4f6d37de589315ff2c99a763f22827da1651ce704f6d5ace69f0dac95bdfbd19905d5c288341bd7867d5741fa3215ed5ce02838145c6ecc7a460fef10e0d958419571a8de8a7cd097627298fbf0b96c45c974e12eeb25c947c71853d9e365a066937e981ba713bd57f5a366531cb02dffa16359af0e9469a52ba8a6a88dc952d5d4fd1de55c0277f55953c50994647d36de030000",
        }
    )
    for txin in txins:
        tx = txs[txin.prev_hash]
        result = unblind(
            client=client,
            txo=tx.vout[txin.prev_index],
            rangeproof=tx.wit.vtxoutwit[txin.prev_index].rangeproof,
        )
        txin.confidential = proto.TxConfidentialAsset(
            asset=LBTC_ASSET,
            amount_blind=bytes(result.blinding_factor.data),
            asset_blind=bytes(result.asset_blinding_factor.data),
        )

    txouts = [
        proto.TxOutputType(
            address=get_confidential_address(client, "44'/1'/0'/0/1"),
            amount=1000_0000,
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
            amount=233_0000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            confidential=proto.TxConfidentialAsset(
                asset=LBTC_ASSET,
                amount_blind=bytes.fromhex(
                    "d64ddd76670705d6b4b04d395c192a7c17e1ead0b5534c10ab7b963951281841"
                ),
                asset_blind=b"\x44" * 32,
                nonce_privkey=b"\xBB" * 32,  # TODO: generate on device
            ),
        ),
        proto.TxOutputType(
            address="",
            amount=1_0000,
            confidential=proto.TxConfidentialAsset(asset=LBTC_ASSET),
        ),  # fee
    ]

    with client:
        client.set_expected_responses(signature_responses(txins, txouts))
        signatures, _ = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    # store signature
    txins[0].multisig.signatures[0] = signatures[0]
    # sign with second key
    txins[0].address_n = parse_path("49'/1'/2'/0/1")

    with client:
        client.set_expected_responses(signature_responses(txins, txouts))
        _, serialized_tx = btc.sign_tx(
            client,
            "Elements",
            txins,
            txouts,
            prev_txes=None,
            details=proto.SignTx(version=2),
        )

    tx = generate_proofs(client=client, tx=serialized_tx, txins=txins, txouts=txouts)
    assert (
        tx.serialize().hex()
        == "020000000101695439f26a32c3463f2f9b417a57dcecbd13f8bf46c8ba44ad7b50bc379804df01000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854097b4baef3255e0e39ed94612bd32bc8d833e7ef66c9bf53e5b95a30f068baf0700268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000002710000000000000000003473044022013d96ddcdf806fdfcecdfaa48e428a7636aae811c5dc4b9df8510279dfdb8158022043dd637b1934349b319e274e9e907e5e47a9fe1702bcaf06bcae8f90049b62820147304402206462ee3d9766a3f2a53adaf581adc22dba96028811cde143f1af0456c75bb17e022037398932de6e5853113772e736b33c4bab707a4aecda0bf08740deeda4666ff40150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac004301000175110e5b4618d858f75b6e7e5527f90d1c9c6c902c22e77dacdee824ccf89f08ba95a398785b6258e785c333a9987032f793ca3a791b047da662d20c8e7fd95dfd0c0a601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd34743010001332176b6973d4c47fe35931024dffc14ac11c6fc030f3e8df0765bb79f46245e9a6176eaf3cc5ad0711f87aa7066b297c3201eec11716aaeac9bc2aeee2c8200fd0c0a601f0000000000000001fe5eb22c3e5a11520ecf38d63d4a00aadc465e7c88881c94e1634e5c0433393d6ea8f832edad0f631eaa1022e1d57ec753be2284be7a419c8fdeb17313f3e02d08d4f8b32b081f7ad6fb14f352634cf00465ba09af10909e02eba675e1bc74b32ab41a8fec2759cb72447a0e9ff3e57df826148ae6f9d7e70334b1313778c0bf148236146de00ae8f6c7b066cd3c31a19ec31bca75aa62e8c9d3f095ed4b31b4f7f0b035d5c109ea62750d03bbb18556889f9951048bf68d52e574460f24970ef1f11ba04de2775528d7a6cd4c8466b69ccace6fc1bd7de66067959e71d93bcbac7ddc2c30b03558d91e99617cec904411491767c31dbca9c1146a85a79e5f13246fe7ea431aca33ab4086b5e068d5b57a4942514e2f6ff910514ce01db2555f391596a616a516527b2e6d94ed9cb702a7ab0cb41f106340284ae214a59993911e820386719037413cca202a57ee930bf66317682ab4c6d186237aba9e843713c4d17914270fb9b249f7b163ea5534add472035fae6a1da4d854125f3ced04e90971728aaed559d5999c2c24bf7b2b3a9439d7c7947944d9ed0e9bf024270b03773a92574c061a2d7937c3d05c431a6ba4554964269479d53800d3ceade4967921a22f51902c36c443082b732b898e167a4a19da713d876736281ce34c294b759b9899ffccacb864b86a320f7552804aaea2b74c390519bc61c516df2b1fc7bed3eae7f466848dbd18bfd07d68b6abc3778c2c1233c469681fcc40c659b763a32f541406b4c5a335d11ef4f41a19a35238ec07374659e4b3387b8f96fe828105a9d454d57eb1a822fac1948e2a9d78e900ba80a4a986c1f2e816308ae0f34a4905533813f1a53339fc0d1200c40fea57241e8073249f0144acbe294d4f1a19f525c05fb34206745c72e9893bb96aae1f2d624bf1cfc1666d27de4d0bd51e5c49a7b04d0678e733189aed0c7fc3ce58bfa4e4e51ccd9b5c75daf67adb7cf8acae23726b6fab8271dfe38077d1a35bbea85255e22e8b44f998bb7dc72c1132af13edd921822eae6018756262f3bb7be961d38efaa6af0901ffb2f16a666d3bdd5feb9de60ff2826a63ea003c729ae461bfc4e3dc64d85cd2cfe50a81ef1a25c87fa05575e0b48da056e3a82422afdf70ae880422d24d5eaa91edb6f81c8d4c667525ff6704f282926a35a7965c81b788ecff256c7ea182916e51a7eef40e8d75e344ae560390180fa44e4e53cf3c682c960debd95783ae0fef461aee62c018db08a3836bac942e5311735616eda3513bee61e35bb4c0a7c029eb962ac8a261cbda1570dfc6271bc66b22e2199b7243935f991826ae5c33e2cd02c92430a047e7d7c1e3e7d34a7cd84145d6d20fafecf169e5107a2d111f2681184c1c65465ad8e2ab228a8d2e8b6e11fef4cdc7be1078432598fd5aa6c2cd701a0de1377b9d6f9975a08bb2b2a235d5fa29e3677b85a111ba5ff0a568bd34820a2a35798c2e3bfe0c033bf329ecf1a62970e808b59e49b8830ebc2ea58abd5c228f9eb2511f169f54bf7133fd9eb2a474869d98cfec623e2db2d89f6088665491c13b261119d871483be66877dc7a63b8253ca12ab1e90fa354de01813aba868c0e3197b807f5134f17775e208fab3ff8bbbb65029d0077e9ef71caf67b52607e1e6a7ad960ab13c2cfe3ffe4ea7970eb240b544f3805a9457be0f81f1d2f2f2fe2d8d0d138e1eed434ef90c4d5b13e827359f04a310d5da3f343b927a7f5cda0f3ba1b087edbf91e006419127aaf370d1744558d95701c5bbbd28321570078001cd53cf05e9be035959cf9616cce6926edd6471ee015a807a395fcb5181bb41c95bea22e13fa3eb57d6d5500915bb6173ed35601cd34ab88502d4b6eb874aef8ddb4b6343c83db2ca0af86c6bb82c0b4516a7ff7a0b03aae08dc09c4ae3912b8f2758c313a9ad605187e888e76254f14156db24ffd103e2dac7783f1ecf69d0dfe921147203c5b268385502c69618a587de5433e114ff6541eb15ada97d0c25f2a955d4026937ad6054574dc9809e92bc79bbe043830a77dd574919135e20b7bf49c4cd6c7f3901d9152fbbaae538b23a652270044cde4de5f01ffef8bc806dc1694e9547ca13479eca12d6fafa32507d130177a3012ec68984073913e18523a841812108afc8f951d72b382f5e4f2acb0192dcd15c53c9ec411ba22b2ad8d8609388e2144fc3055638a2f174decaf4b13fec7cb3890842f5abc1c4106dbe158fa35f85580f2072dc8dbbde594be197264bff508478944d2c2046d3b61a05e5ece89c57709e51ca37737cf3be77771f39bb795d7824d0281a173c0afdee996c628c94e8e18a6376d7d015e420410e162d440076dd7f1f9d3d64599d2ead57714347f65aea7b53459bfd2ea82119d8966dccf207dd803e5ac4d06adf6cf2301ab2136a0e618e914f94b5ea917caba183835039d3178e7cacc1fd078d0243a18a9b988da3aafb0fbae62c93eb38dfd5fec07f7de1542a635daf5f95d066134b14960cc6737792f541c6d25e40cdc1675bc75043e06adf95106eece45bf184c85b37e5aba19162a62c46f9cff659191e7b3fbca707c54bf7f9ab86cc28632b64246deca613b216a47fa162d88c9beceae945545ff875e528122126a2cc8d2812909fc5cb082c7997f7faa56bb12d585122495307946b4627d88a37da38b480e3ab0ae9eb04a756444875608016ba503dbed0a61b50748fb132f4ffbbaefef66d5c04bded6425bb0012532842bfc1e14a3c8fdc10a667e78aca23ac5bda789d97b85e0d450753c877e3f48947a3776cd17ee30d51a99b46f29fdffce14c125ed4e81a166cf33211ee334f4d39236fb88d4a1213652092039ea901116ca9786b6b1d504f0edbbeb5db25bde9945a0fbb16d0db4f27a65f851d38487f423b680072dd2ca1529f3c2a7e6be1fc1850b17125d1032050ad58928b84f16e72899fe0904cfa800740dd1f12d7cf7594baae5c83ebc754cba61020b020bed2d415fea08069540bad9060a9087d616d73944b338a03540cc20def155a5feded6aef215b90117d21441baab70a97bafe61caf63c4f787796ad3851fe96106118011c9862c839bee78d863f009f59c728eb6b19383f59ebaa93c1a5e41d512bff6bf4f6fb096697228514c15a99e00836b80a197ce8323202fd5ce9fd7334a3693a8d92e2d25d5385cd334870e15e7466c1a49c496f5b25eccfacf3e405a2ba49fdf196742234158ac95d528cf80ba955442f6890e4c92f1b01f0c6fcdd2f47328375bc0f981a89cf56903a158d3c8d56f3331a9428cd399693561b422f076c280026995f9282b3e5ccaedae53358b2df46c3eea0977c7724a5a9ed9e6cd4925d9f4862e579e22a1187c97546414eb230778c3485447272cc39669fe4d5a185d2e917be975f2276efbd9ab7158d5fb5b06ca60ffcfc4a2ef13204b1bcb5e1ac9ed6e368cf822eeb6af2a38bb9f31b205f794dadbdb36f4cca87c2c125cf4fb77c3a1515d03a833bce7597c89957c8b199b0fda72d60761bfddcbbd214e8b1f6555c6015a136eeaf2dd408a78945cd9c6cf5574fc999dc3e90d6d7be344008fa947906c6bcff3c766a6feb36bfe1834880000"
    )


# $ e1-cli getrawtransaction d06d594deaed0ec821724d5e1ad0e6697383b624f2b73ba6894cad5f25820702 1
# {
#   "txid": "d06d594deaed0ec821724d5e1ad0e6697383b624f2b73ba6894cad5f25820702",
#   "hash": "049d6e67b4cb06bf7d72fbca83394cc9dbe2f97ebd9b18aad78aa8a3e542f0dd",
#   "wtxid": "049d6e67b4cb06bf7d72fbca83394cc9dbe2f97ebd9b18aad78aa8a3e542f0dd",
#   "withash": "f4a63f0000e0cfd68c6f028b7d39819d9a0d87e94582c82b6ba30cd1590a763b",
#   "version": 2,
#   "size": 5894,
#   "vsize": 1757,
#   "weight": 7025,
#   "locktime": 0,
#   "vin": [
#     {
#       "txid": "df049837bc507bad44bac846bff813bdecdc577a419b2f3f46c3326af2395469",
#       "vout": 1,
#       "scriptSig": {
#         "asm": "00207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1",
#         "hex": "2200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1"
#       },
#       "is_pegin": false,
#       "sequence": 4294967295,
#       "txinwitness": [
#         "3044022013d96ddcdf806fdfcecdfaa48e428a7636aae811c5dc4b9df8510279dfdb8158022043dd637b1934349b319e274e9e907e5e47a9fe1702bcaf06bcae8f90049b628201",
#         "304402206462ee3d9766a3f2a53adaf581adc22dba96028811cde143f1af0456c75bb17e022037398932de6e5853113772e736b33c4bab707a4aecda0bf08740deeda4666ff401",
#         "748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac"
#       ]
#     }
#   ],
#   "vout": [
#     {
#       "value-minimum": 0.00000001,
#       "value-maximum": 42.94967296,
#       "ct-exponent": 0,
#       "ct-bits": 32,
#       "valuecommitment": "09c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf",
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
#       "valuecommitment": "097b4baef3255e0e39ed94612bd32bc8d833e7ef66c9bf53e5b95a30f068baf070",
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
#   "hex": "020000000101695439f26a32c3463f2f9b417a57dcecbd13f8bf46c8ba44ad7b50bc379804df01000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff030bdd90421489b0cf1c5da16526eb6855973aacf6082b64058d7bbfb281955ac65209c1c777edffaa046c732ee7c25dff13218a5815063cc44feae4fef489ac945adf026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb317a91434fbecbc9786f628943d2abf87d66957bb6b35d0870bb3fa72df355fb6caa1797e134def9110892f182c50e7eff4e03adaad7e810854097b4baef3255e0e39ed94612bd32bc8d833e7ef66c9bf53e5b95a30f068baf0700268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b517a9140de6434adf2f3912732cdc20db3e2145a00e61e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000002710000000000000000003473044022013d96ddcdf806fdfcecdfaa48e428a7636aae811c5dc4b9df8510279dfdb8158022043dd637b1934349b319e274e9e907e5e47a9fe1702bcaf06bcae8f90049b62820147304402206462ee3d9766a3f2a53adaf581adc22dba96028811cde143f1af0456c75bb17e022037398932de6e5853113772e736b33c4bab707a4aecda0bf08740deeda4666ff40150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac004301000175110e5b4618d858f75b6e7e5527f90d1c9c6c902c22e77dacdee824ccf89f08ba95a398785b6258e785c333a9987032f793ca3a791b047da662d20c8e7fd95dfd0c0a601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd34743010001332176b6973d4c47fe35931024dffc14ac11c6fc030f3e8df0765bb79f46245e9a6176eaf3cc5ad0711f87aa7066b297c3201eec11716aaeac9bc2aeee2c8200fd0c0a601f0000000000000001fe5eb22c3e5a11520ecf38d63d4a00aadc465e7c88881c94e1634e5c0433393d6ea8f832edad0f631eaa1022e1d57ec753be2284be7a419c8fdeb17313f3e02d08d4f8b32b081f7ad6fb14f352634cf00465ba09af10909e02eba675e1bc74b32ab41a8fec2759cb72447a0e9ff3e57df826148ae6f9d7e70334b1313778c0bf148236146de00ae8f6c7b066cd3c31a19ec31bca75aa62e8c9d3f095ed4b31b4f7f0b035d5c109ea62750d03bbb18556889f9951048bf68d52e574460f24970ef1f11ba04de2775528d7a6cd4c8466b69ccace6fc1bd7de66067959e71d93bcbac7ddc2c30b03558d91e99617cec904411491767c31dbca9c1146a85a79e5f13246fe7ea431aca33ab4086b5e068d5b57a4942514e2f6ff910514ce01db2555f391596a616a516527b2e6d94ed9cb702a7ab0cb41f106340284ae214a59993911e820386719037413cca202a57ee930bf66317682ab4c6d186237aba9e843713c4d17914270fb9b249f7b163ea5534add472035fae6a1da4d854125f3ced04e90971728aaed559d5999c2c24bf7b2b3a9439d7c7947944d9ed0e9bf024270b03773a92574c061a2d7937c3d05c431a6ba4554964269479d53800d3ceade4967921a22f51902c36c443082b732b898e167a4a19da713d876736281ce34c294b759b9899ffccacb864b86a320f7552804aaea2b74c390519bc61c516df2b1fc7bed3eae7f466848dbd18bfd07d68b6abc3778c2c1233c469681fcc40c659b763a32f541406b4c5a335d11ef4f41a19a35238ec07374659e4b3387b8f96fe828105a9d454d57eb1a822fac1948e2a9d78e900ba80a4a986c1f2e816308ae0f34a4905533813f1a53339fc0d1200c40fea57241e8073249f0144acbe294d4f1a19f525c05fb34206745c72e9893bb96aae1f2d624bf1cfc1666d27de4d0bd51e5c49a7b04d0678e733189aed0c7fc3ce58bfa4e4e51ccd9b5c75daf67adb7cf8acae23726b6fab8271dfe38077d1a35bbea85255e22e8b44f998bb7dc72c1132af13edd921822eae6018756262f3bb7be961d38efaa6af0901ffb2f16a666d3bdd5feb9de60ff2826a63ea003c729ae461bfc4e3dc64d85cd2cfe50a81ef1a25c87fa05575e0b48da056e3a82422afdf70ae880422d24d5eaa91edb6f81c8d4c667525ff6704f282926a35a7965c81b788ecff256c7ea182916e51a7eef40e8d75e344ae560390180fa44e4e53cf3c682c960debd95783ae0fef461aee62c018db08a3836bac942e5311735616eda3513bee61e35bb4c0a7c029eb962ac8a261cbda1570dfc6271bc66b22e2199b7243935f991826ae5c33e2cd02c92430a047e7d7c1e3e7d34a7cd84145d6d20fafecf169e5107a2d111f2681184c1c65465ad8e2ab228a8d2e8b6e11fef4cdc7be1078432598fd5aa6c2cd701a0de1377b9d6f9975a08bb2b2a235d5fa29e3677b85a111ba5ff0a568bd34820a2a35798c2e3bfe0c033bf329ecf1a62970e808b59e49b8830ebc2ea58abd5c228f9eb2511f169f54bf7133fd9eb2a474869d98cfec623e2db2d89f6088665491c13b261119d871483be66877dc7a63b8253ca12ab1e90fa354de01813aba868c0e3197b807f5134f17775e208fab3ff8bbbb65029d0077e9ef71caf67b52607e1e6a7ad960ab13c2cfe3ffe4ea7970eb240b544f3805a9457be0f81f1d2f2f2fe2d8d0d138e1eed434ef90c4d5b13e827359f04a310d5da3f343b927a7f5cda0f3ba1b087edbf91e006419127aaf370d1744558d95701c5bbbd28321570078001cd53cf05e9be035959cf9616cce6926edd6471ee015a807a395fcb5181bb41c95bea22e13fa3eb57d6d5500915bb6173ed35601cd34ab88502d4b6eb874aef8ddb4b6343c83db2ca0af86c6bb82c0b4516a7ff7a0b03aae08dc09c4ae3912b8f2758c313a9ad605187e888e76254f14156db24ffd103e2dac7783f1ecf69d0dfe921147203c5b268385502c69618a587de5433e114ff6541eb15ada97d0c25f2a955d4026937ad6054574dc9809e92bc79bbe043830a77dd574919135e20b7bf49c4cd6c7f3901d9152fbbaae538b23a652270044cde4de5f01ffef8bc806dc1694e9547ca13479eca12d6fafa32507d130177a3012ec68984073913e18523a841812108afc8f951d72b382f5e4f2acb0192dcd15c53c9ec411ba22b2ad8d8609388e2144fc3055638a2f174decaf4b13fec7cb3890842f5abc1c4106dbe158fa35f85580f2072dc8dbbde594be197264bff508478944d2c2046d3b61a05e5ece89c57709e51ca37737cf3be77771f39bb795d7824d0281a173c0afdee996c628c94e8e18a6376d7d015e420410e162d440076dd7f1f9d3d64599d2ead57714347f65aea7b53459bfd2ea82119d8966dccf207dd803e5ac4d06adf6cf2301ab2136a0e618e914f94b5ea917caba183835039d3178e7cacc1fd078d0243a18a9b988da3aafb0fbae62c93eb38dfd5fec07f7de1542a635daf5f95d066134b14960cc6737792f541c6d25e40cdc1675bc75043e06adf95106eece45bf184c85b37e5aba19162a62c46f9cff659191e7b3fbca707c54bf7f9ab86cc28632b64246deca613b216a47fa162d88c9beceae945545ff875e528122126a2cc8d2812909fc5cb082c7997f7faa56bb12d585122495307946b4627d88a37da38b480e3ab0ae9eb04a756444875608016ba503dbed0a61b50748fb132f4ffbbaefef66d5c04bded6425bb0012532842bfc1e14a3c8fdc10a667e78aca23ac5bda789d97b85e0d450753c877e3f48947a3776cd17ee30d51a99b46f29fdffce14c125ed4e81a166cf33211ee334f4d39236fb88d4a1213652092039ea901116ca9786b6b1d504f0edbbeb5db25bde9945a0fbb16d0db4f27a65f851d38487f423b680072dd2ca1529f3c2a7e6be1fc1850b17125d1032050ad58928b84f16e72899fe0904cfa800740dd1f12d7cf7594baae5c83ebc754cba61020b020bed2d415fea08069540bad9060a9087d616d73944b338a03540cc20def155a5feded6aef215b90117d21441baab70a97bafe61caf63c4f787796ad3851fe96106118011c9862c839bee78d863f009f59c728eb6b19383f59ebaa93c1a5e41d512bff6bf4f6fb096697228514c15a99e00836b80a197ce8323202fd5ce9fd7334a3693a8d92e2d25d5385cd334870e15e7466c1a49c496f5b25eccfacf3e405a2ba49fdf196742234158ac95d528cf80ba955442f6890e4c92f1b01f0c6fcdd2f47328375bc0f981a89cf56903a158d3c8d56f3331a9428cd399693561b422f076c280026995f9282b3e5ccaedae53358b2df46c3eea0977c7724a5a9ed9e6cd4925d9f4862e579e22a1187c97546414eb230778c3485447272cc39669fe4d5a185d2e917be975f2276efbd9ab7158d5fb5b06ca60ffcfc4a2ef13204b1bcb5e1ac9ed6e368cf822eeb6af2a38bb9f31b205f794dadbdb36f4cca87c2c125cf4fb77c3a1515d03a833bce7597c89957c8b199b0fda72d60761bfddcbbd214e8b1f6555c6015a136eeaf2dd408a78945cd9c6cf5574fc999dc3e90d6d7be344008fa947906c6bcff3c766a6feb36bfe1834880000",
#   "blockhash": "e8b62fcf4315504b4d8b45b2ba70df0ed3cb8ffd93cb7fc4b51578933740fb2c",
#   "confirmations": 1,
#   "time": 1579341234,
#   "blocktime": 1579341234,
#   "ToString": "CTransaction(hash=d06d594dea, ver=2, vin.size=1, vout.size=3, nLockTime=0)\n    CTxIn(COutPoint(df049837bc, 1), scriptSig=2200207b6de8dfee7092963c)\n    CScriptWitness(3044022013d96ddcdf806fdfcecdfaa48e428a7636aae811c5dc4b9df8510279dfdb8158022043dd637b1934349b319e274e9e907e5e47a9fe1702bcaf06bcae8f90049b628201, 304402206462ee3d9766a3f2a53adaf581adc22dba96028811cde143f1af0456c75bb17e022037398932de6e5853113772e736b33c4bab707a4aecda0bf08740deeda4666ff401, 748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a91434fbecbc9786f628943d2abf87)\n    CTxOut(nAsset=CONFIDENTIAL, nValue=CONFIDENTIAL, scriptPubKey=a9140de6434adf2f3912732cdc20db)\n    CTxOut(nAsset=b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23, nValue=0.00010000, scriptPubKey=)\n    01000175110e5b4618d858f75b6e7e5527f90d1c9c6c902c22e77dacdee824ccf89f08ba95a398785b6258e785c333a9987032f793ca3a791b047da662d20c8e7fd95d\n    601f0000000000000001e411513922b6b62dc5aa5a23f74836aefac52477696cfacda48f78cedbe97685494a24b9815c013cbbb29808415999814083cdd26ab1438ca6bd106f54cf306e81a560b4cc34e640a34d8721e2ed7c60522c73b41e6cf0a2645621ec61038772f3ab4e5f21a2f8a5529fc23767fcaebd2cbbc00efea801805efe714bc5411d0cd3ac57ed5a317827252d804b6067eb540dc863995fdb281dbc2d30ff00945edc503c79d2dc6a873a092173026d57940af3855b8443c0705d37822f64ff1474b72628ba76be3b530459352cc1fe2ac6b244112fba1cafb16dafa05514960b3fde9278edb3ffe65ebd083d457c6d5c0f73b1bb7b8ba4740b040c553618eda2ce5329ad61523cfd91d06d92b1fc554ce4f8b81080c682ab5e241861dd344ebb8e8f5b50558200eb68561f43febf169f3ce5889d6d1888241dcb8dea3398c95878056075e9696e00566ba3f3f45647dea92fd332ccd18c537cc4b878f06ee387c928c3f2ee55c86ed702ba242231cf6a2a355fa95de87717d49d49a5e7f53a4a0901cb221a4f30aa27538f6e89a82747605bce82c94f4b54b17421cb11bb4fc17da116549cf5ccf720c7342f5e8be9eb81792b60e542bfa884403c10e51a4865f8c84351191fdfd378d82e79b97f5d7d74298ea27e93ad96753deb0756ea3986776f8eb4baa0472edd15c5921ea5cbc530d916b65ef28855fef1069193c386a85d2a251fc99ae0e3cc4036cc0a3ff2e59ae6f5f4cf0da12a64863fa1c1cbc548766b993d7041703c521ab5746afb6bb6079e9e3046b2bb2e666d568d4f155bb19518be3afb0e0a34d0c29b6a5e9010f91feb59289b260a211eccea1d48bc2f9d9359675bb07b177f5869b9121f8fd06938f7e0c0c5f1b1d57301cdcb93605048b6bb974c7e2c1e2a0e0f54f3afae38de3a963f5b1d84ce7fbac6e2f96cd7190e2bfc1326d9b3a444fb139fab5e6582d702e33b6b9933471b0d0164b889d44dd443a90356c58e9c8c6b902ee014f1ffa5531634dcadb5d3d3fa00de8d24ef7b3e627b398988abe46a40cfa7bfb8ffd086e9b1b0893893cbb63578713ed68835f24c7983f46f38fb4f9723bc562456f2d2ca010231408f4c3af3df55652feb22c8c2b679182ceebccf4b4cb48f2279692dfa62174665f1fc6b709ec4873cc5cf741c06ab3f811d7832fcda5c826e196421b1fe19728d862d42ea0a149a91f60b4395e068e585936a8ce56e6fb33dfd5b908079ee4c38f4f76d57494be13172c53c885e83c260639e5aeaf2741c91bf43a91f89b13866b10250c71b33a89292903f93008a59d0b386ded356c3d7e2ba3bc9291bd6bfda41fcdbe343d14df89a325044eb07fa384f815c85e1b4c28390ac047624e6113d0ddd3934ed5f13bc52b83b335731160268c1a03b8171acc18e2053f55b44d80db123a43dbdcbd08fee1eec3d21dfc732cb64b54b82037cdb4c1161c1890996c605a70fe2325f6bd429ae5a92a9a0f3015c90be83fa0a13826a015b86acdfd904b576fcb3edfc9f130c6898fe1e6161239d139092d4161e1de037de54b46feb67bdc686538dbaba532fb0d812e669805d0aec2177d6f3ff0ae9b603986a0493dc16f3d8af336b0d7d049ce22641d46715dfc2b677e058ed346b166576ff6a905f40bc9ad9c56346c69074188d2239207cad0ba6fac882c35615e1fb9a33276e2ea4dd3fe05a4c86efab2f499d6295d43d374f93b209401df095454df63ff44aa4caac49d8bedca233ce097a10eaadfa446251adfd64e04cbf1c6b11e5066338aee975680e01c9aa4bdce9e913a45d837ecf686b65954b0d541391d0374addc7151116e088306bce1cc0140c9af6381055f5f0bdafccbca852f7f2ceb43e2635fa9e0e57627e90a47fbd47df831b8d78215b531bcf5bffa643f81c467bf5c467472b6930e07c935810fa5409d4d0e5e7d2a725055e00dcedc14942734d05710edfd281703a21ce07474a6271c93ec43d9aeb8e269761b040de01038a5fb915611f89949c7b93f9c5af9db48c8fba3378ef3dd8be6c1242f843d5e9245ec61aa1c26b98c27a9904fefde4f6a25c8c5ce8e213ae8d1f47a3bf8b7e3cd456d90f9a5aa963e60a5100ba4ceadb5778719db7a7a427188c28e0a75f345023f2638d15b25b3175d97742a34270c3b0de713ea86dd80c47531b7fa886530b07c3330d476173d51a64f49bbf702402d7fb8c738465f55c580da41e0fd0be0a8e3f6cd45ce918bbe124227155564e04fa9aba857066f388f1cb9a85fd9c896309ee750530ba195723a0809463da3be4ea8ef74ae8a7d4d6ac20811b68b562be55c71b6c64e491e7c48077a7a50dc13e3b26b94ccb6bf571a78a8d276c1741c2813b6d87f75c4150d4cb0c7edc2528c827adf3e2dd91c44a9e4f81c8c0b48437f1727b7ff05ef9e5d9df563adf168a6ea35f627923ac1fc7019270da031b151464e8c9f7f635c7e7a289106547d5bf33d8bb6fb38d1ff9933a0894a0deb5093110e9efaa89854592e9a0882f5bdc7242f7e772e6d2cb0b96393982e473cd0d0f48ea0dbd64a46939102283f31585489cd52f67404f0f0ce50c35ae71c97c6e502fffbb6b528e7128b6cd1be41cb920e63f8e67a5917d5e3f1d9ad0def5ee9f4a851066950ffc02061bea46d1d7a3ab614146f2f125cffedfbee3caf7fc4c36ae0f3fbdabe32f3f66a6e5bd7a1f3f99bc2777a2181aa98faa1be50501ac004a71b9f07e4eee1fed82e0e8f167f35d397d8df9f76805b8ab0ce47968fb994d70f2706f79fe975fb820ab35f1995641a1eb389bf2a9fc9eacd5c4b4795cc8a6abbda92c6f6ad7f611b1773d69056b9f86705e80e9baeb7b4e815e468d5fbfdecdf214920492b9c7b365e9d5381801ea2e645cc690896e1eb1b4763ad2b2f721b3c6345606a98a0761f411acf88d6373d26969603fc6f24820315f6d7a8a6ea67d322f07f3adfd702f411b7292107cb08b8568bda02cbc0a971899966fb6bcbc6eb9d9cd422dc9d108416d8caf24a402532a41621546e42d68d43ced170b9230262c7689067da0b14711c48447b74a6d260839c3bb579a4169bf5f56ad21880a4ac6ee9583a48e5a8e3532c060563b6a386e86375bb76e928a8bb561303409c4e8676503e1e91ed52af18cd92bca7e75b0c43f7f1841399c53b78fba5a439f0e4c7c1e44f6b94dbb9a425ec23c31e21e2a57b7e3f1a88b999965fbdb8b193689a5470a4215e1f529ce896eff6e557480baf1b07232cf89ed89ae19a3bfa502127c52c30c52b98739364c8cdbfda82bfec3ce1109d5cdcd8bdea5c06811d4cb79a7791679070c70697db94232fc65d2b7531d7eeba3d51e463303f40fe1838ad33effb46b1ca6d09e7233ab0ca762b84d323121df9c4e1a602d4b0b7c1201ae2d74b795dccb96699b4f3f469a35ff4a7b3dbc937fe1615a5d40b50606a9bd65032e226fd186f929655500e3c4ab77a9380722416bd88be9462a7f492f1f1f9bc773a3607f8fe4d5115212742a4f64a7e4d46ca8bc6a53c1071fdef51e6139d4c8e84cad9265963e150aa7b3a69ce1c967deaa1bf67955c1cb2a9e286b9ba8c817691b4d16bf1ec06e9b815afdd37ca763b54df80eacd347\n    010001332176b6973d4c47fe35931024dffc14ac11c6fc030f3e8df0765bb79f46245e9a6176eaf3cc5ad0711f87aa7066b297c3201eec11716aaeac9bc2aeee2c8200\n    601f0000000000000001fe5eb22c3e5a11520ecf38d63d4a00aadc465e7c88881c94e1634e5c0433393d6ea8f832edad0f631eaa1022e1d57ec753be2284be7a419c8fdeb17313f3e02d08d4f8b32b081f7ad6fb14f352634cf00465ba09af10909e02eba675e1bc74b32ab41a8fec2759cb72447a0e9ff3e57df826148ae6f9d7e70334b1313778c0bf148236146de00ae8f6c7b066cd3c31a19ec31bca75aa62e8c9d3f095ed4b31b4f7f0b035d5c109ea62750d03bbb18556889f9951048bf68d52e574460f24970ef1f11ba04de2775528d7a6cd4c8466b69ccace6fc1bd7de66067959e71d93bcbac7ddc2c30b03558d91e99617cec904411491767c31dbca9c1146a85a79e5f13246fe7ea431aca33ab4086b5e068d5b57a4942514e2f6ff910514ce01db2555f391596a616a516527b2e6d94ed9cb702a7ab0cb41f106340284ae214a59993911e820386719037413cca202a57ee930bf66317682ab4c6d186237aba9e843713c4d17914270fb9b249f7b163ea5534add472035fae6a1da4d854125f3ced04e90971728aaed559d5999c2c24bf7b2b3a9439d7c7947944d9ed0e9bf024270b03773a92574c061a2d7937c3d05c431a6ba4554964269479d53800d3ceade4967921a22f51902c36c443082b732b898e167a4a19da713d876736281ce34c294b759b9899ffccacb864b86a320f7552804aaea2b74c390519bc61c516df2b1fc7bed3eae7f466848dbd18bfd07d68b6abc3778c2c1233c469681fcc40c659b763a32f541406b4c5a335d11ef4f41a19a35238ec07374659e4b3387b8f96fe828105a9d454d57eb1a822fac1948e2a9d78e900ba80a4a986c1f2e816308ae0f34a4905533813f1a53339fc0d1200c40fea57241e8073249f0144acbe294d4f1a19f525c05fb34206745c72e9893bb96aae1f2d624bf1cfc1666d27de4d0bd51e5c49a7b04d0678e733189aed0c7fc3ce58bfa4e4e51ccd9b5c75daf67adb7cf8acae23726b6fab8271dfe38077d1a35bbea85255e22e8b44f998bb7dc72c1132af13edd921822eae6018756262f3bb7be961d38efaa6af0901ffb2f16a666d3bdd5feb9de60ff2826a63ea003c729ae461bfc4e3dc64d85cd2cfe50a81ef1a25c87fa05575e0b48da056e3a82422afdf70ae880422d24d5eaa91edb6f81c8d4c667525ff6704f282926a35a7965c81b788ecff256c7ea182916e51a7eef40e8d75e344ae560390180fa44e4e53cf3c682c960debd95783ae0fef461aee62c018db08a3836bac942e5311735616eda3513bee61e35bb4c0a7c029eb962ac8a261cbda1570dfc6271bc66b22e2199b7243935f991826ae5c33e2cd02c92430a047e7d7c1e3e7d34a7cd84145d6d20fafecf169e5107a2d111f2681184c1c65465ad8e2ab228a8d2e8b6e11fef4cdc7be1078432598fd5aa6c2cd701a0de1377b9d6f9975a08bb2b2a235d5fa29e3677b85a111ba5ff0a568bd34820a2a35798c2e3bfe0c033bf329ecf1a62970e808b59e49b8830ebc2ea58abd5c228f9eb2511f169f54bf7133fd9eb2a474869d98cfec623e2db2d89f6088665491c13b261119d871483be66877dc7a63b8253ca12ab1e90fa354de01813aba868c0e3197b807f5134f17775e208fab3ff8bbbb65029d0077e9ef71caf67b52607e1e6a7ad960ab13c2cfe3ffe4ea7970eb240b544f3805a9457be0f81f1d2f2f2fe2d8d0d138e1eed434ef90c4d5b13e827359f04a310d5da3f343b927a7f5cda0f3ba1b087edbf91e006419127aaf370d1744558d95701c5bbbd28321570078001cd53cf05e9be035959cf9616cce6926edd6471ee015a807a395fcb5181bb41c95bea22e13fa3eb57d6d5500915bb6173ed35601cd34ab88502d4b6eb874aef8ddb4b6343c83db2ca0af86c6bb82c0b4516a7ff7a0b03aae08dc09c4ae3912b8f2758c313a9ad605187e888e76254f14156db24ffd103e2dac7783f1ecf69d0dfe921147203c5b268385502c69618a587de5433e114ff6541eb15ada97d0c25f2a955d4026937ad6054574dc9809e92bc79bbe043830a77dd574919135e20b7bf49c4cd6c7f3901d9152fbbaae538b23a652270044cde4de5f01ffef8bc806dc1694e9547ca13479eca12d6fafa32507d130177a3012ec68984073913e18523a841812108afc8f951d72b382f5e4f2acb0192dcd15c53c9ec411ba22b2ad8d8609388e2144fc3055638a2f174decaf4b13fec7cb3890842f5abc1c4106dbe158fa35f85580f2072dc8dbbde594be197264bff508478944d2c2046d3b61a05e5ece89c57709e51ca37737cf3be77771f39bb795d7824d0281a173c0afdee996c628c94e8e18a6376d7d015e420410e162d440076dd7f1f9d3d64599d2ead57714347f65aea7b53459bfd2ea82119d8966dccf207dd803e5ac4d06adf6cf2301ab2136a0e618e914f94b5ea917caba183835039d3178e7cacc1fd078d0243a18a9b988da3aafb0fbae62c93eb38dfd5fec07f7de1542a635daf5f95d066134b14960cc6737792f541c6d25e40cdc1675bc75043e06adf95106eece45bf184c85b37e5aba19162a62c46f9cff659191e7b3fbca707c54bf7f9ab86cc28632b64246deca613b216a47fa162d88c9beceae945545ff875e528122126a2cc8d2812909fc5cb082c7997f7faa56bb12d585122495307946b4627d88a37da38b480e3ab0ae9eb04a756444875608016ba503dbed0a61b50748fb132f4ffbbaefef66d5c04bded6425bb0012532842bfc1e14a3c8fdc10a667e78aca23ac5bda789d97b85e0d450753c877e3f48947a3776cd17ee30d51a99b46f29fdffce14c125ed4e81a166cf33211ee334f4d39236fb88d4a1213652092039ea901116ca9786b6b1d504f0edbbeb5db25bde9945a0fbb16d0db4f27a65f851d38487f423b680072dd2ca1529f3c2a7e6be1fc1850b17125d1032050ad58928b84f16e72899fe0904cfa800740dd1f12d7cf7594baae5c83ebc754cba61020b020bed2d415fea08069540bad9060a9087d616d73944b338a03540cc20def155a5feded6aef215b90117d21441baab70a97bafe61caf63c4f787796ad3851fe96106118011c9862c839bee78d863f009f59c728eb6b19383f59ebaa93c1a5e41d512bff6bf4f6fb096697228514c15a99e00836b80a197ce8323202fd5ce9fd7334a3693a8d92e2d25d5385cd334870e15e7466c1a49c496f5b25eccfacf3e405a2ba49fdf196742234158ac95d528cf80ba955442f6890e4c92f1b01f0c6fcdd2f47328375bc0f981a89cf56903a158d3c8d56f3331a9428cd399693561b422f076c280026995f9282b3e5ccaedae53358b2df46c3eea0977c7724a5a9ed9e6cd4925d9f4862e579e22a1187c97546414eb230778c3485447272cc39669fe4d5a185d2e917be975f2276efbd9ab7158d5fb5b06ca60ffcfc4a2ef13204b1bcb5e1ac9ed6e368cf822eeb6af2a38bb9f31b205f794dadbdb36f4cca87c2c125cf4fb77c3a1515d03a833bce7597c89957c8b199b0fda72d60761bfddcbbd214e8b1f6555c6015a136eeaf2dd408a78945cd9c6cf5574fc999dc3e90d6d7be344008fa947906c6bcff3c766a6feb36bfe183488\n    \n    \n"
# }


def signature_responses(txins, txouts, sign_confirms=1):
    txin_requests = [
        proto.TxRequest(
            request_type=proto.RequestType.TXINPUT,
            details=proto.TxRequestDetailsType(request_index=i),
        )
        for i in range(len(txins))
    ]
    txout_requests = [
        proto.TxRequest(
            request_type=proto.RequestType.TXOUTPUT,
            details=proto.TxRequestDetailsType(request_index=i),
        )
        for i in range(len(txouts))
    ]

    responses = []
    # Stream 1st time - for fee computation and output confirmation.
    responses.extend(txin_requests)
    for txout_request in txout_requests:
        responses.append(txout_request)
        responses.append(
            proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput)
        )

    # Confirm signing
    responses.extend(
        [proto.ButtonRequest(code=proto.ButtonRequestType.SignTx)] * sign_confirms
    )

    # Stream 2nd time - for actual signing & serialization
    responses.extend(txin_requests)
    responses.extend(txout_requests)

    # Stream 3rd time - for witness construction
    responses.extend(txin_requests)
    for o in txout_requests:
        responses.append(o)
        responses.append(o)

    responses.append(proto.TxRequest(request_type=proto.RequestType.TXFINISHED))
