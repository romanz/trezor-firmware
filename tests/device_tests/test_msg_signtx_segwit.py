# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import btc, messages as proto
from trezorlib.ckd_public import deserialize
from trezorlib.tools import H_, CallException, parse_path

from ..tx_cache import tx_cache

TX_API = tx_cache("Testnet")


class TestMsgSigntxSegwit:
    def test_send_p2sh(self, client):
        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=bytes.fromhex(
                "20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        )
        out1 = proto.TxOutputType(
            address="mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC",
            amount=12300000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address="2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX",
            script_type=proto.OutputScriptType.PAYTOADDRESS,
            amount=123456789 - 11000 - 12300000,
        )
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
                client, "Testnet", [inp1], [out1, out2], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100ccd253bfdf8a5593cd7b6701370c531199f0f05a418cd547dfc7da3f21515f0f02203fa08a0753688871c220648f9edadbdb98af42e5d8269364a326572cf703895b012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000"
        )

    def test_send_p2sh_change(self, client):
        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=bytes.fromhex(
                "20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        )
        out1 = proto.TxOutputType(
            address="mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC",
            amount=12300000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            script_type=proto.OutputScriptType.PAYTOP2SHWITNESS,
            amount=123456789 - 11000 - 12300000,
        )
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
                client, "Testnet", [inp1], [out1, out2], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a91458b53ea7f832e8f096e896b8713a8c6df0e892ca8702483045022100ccd253bfdf8a5593cd7b6701370c531199f0f05a418cd547dfc7da3f21515f0f02203fa08a0753688871c220648f9edadbdb98af42e5d8269364a326572cf703895b012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000"
        )

    def test_testnet_segwit_big_amount(self, client):
        # This test is testing transaction with amount bigger than fits to uint32

        inp1 = proto.TxInputType(
            address_n=parse_path("m/49'/1'/0'/0/0"),
            amount=2 ** 32 + 1,
            prev_hash=b"\xff" * 32,
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        )
        out1 = proto.TxOutputType(
            address="2Mt7P2BAfE922zmfXrdcYTLyR7GUvbwSEns",  # seed allallall, bip32: m/49'/1'/0'/0/1, script type:p2shsegwit
            amount=2 ** 32 + 1,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(client, "Testnet", [inp1], [out1])
        assert (
            serialized_tx.hex()
            == "01000000000101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000171600140099a7ecbd938ed1839f5f6bf6d50933c6db9d5cffffffff01010000000100000017a914097c569095163e84475d07aa95a1f736df895b7b8702483045022100cb9d3aa7a8064702e6b61c20c7fb9cb672c69d3786cf5efef8ad6d90136ca7d8022065119ff6c6e6e6960e6508fc5360359bb269bb25ef8d90019decaa0a050cc45a0121033add1f0e8e3c3136f7428dd4a4de1057380bd311f5b0856e2269170b4ffa65bf00000000"
        )

    @pytest.mark.multisig
    def test_send_multisig_1(self, client):
        nodes = [
            btc.get_public_node(client, parse_path("49'/1'/%d'" % i)).node
            for i in range(1, 4)
        ]

        multisig = proto.MultisigRedeemScriptType(
            nodes=nodes, address_n=[1, 0], signatures=[b"", b"", b""], m=2
        )

        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/1'/1/0"),
            prev_hash=bytes.fromhex(
                "9c31922be756c06d02167656465c8dc83bb553bf386a3f478ae65b5c021002be"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=1610436,
        )

        out1 = proto.TxOutputType(
            address="mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC",
            amount=1605000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )

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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            signatures, _ = btc.sign_tx(
                client, "Testnet", [inp1], [out1], prev_txes=TX_API
            )
            # store signature
            inp1.multisig.signatures[0] = signatures[0]
            # sign with third key
            inp1.address_n[2] = H_(3)
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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                client, "Testnet", [inp1], [out1], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "01000000000101be0210025c5be68a473f6a38bf53b53bc88d5c46567616026dc056e72b92319c0100000023220020cf28684ff8a6dda1a7a9704dde113ddfcf236558da5ce35ad3f8477474dbdaf7ffffffff01887d1800000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac040047304402203fc3fbe6cd6250d82ace4a585debc07587c07d2efc8bb56558c91e1f810fe65402206025bd9a4e80960f617b6e5bfdd568e34aa085d093471b7976e6b14c2a2402a7014730440220327abf491a57964d75c67fad204eb782fa74aa4abde40e5ad30fb0b7696102b7022049e31f2302417be0a87e2f818b93a862a7e67d4178b7cbeee680264f0882113f0169522103d54ab3c8b81cb7f8f8088df4c62c105e8acaa2fb53b180f6bc6f922faecf3fdc21036aa47994f3f18f0976d6073ca79997003c3fa29c4f93907998fefc1151b4529b2102a092580f2828272517c402da9461425c5032860ab40180e041fbbb88ea2a520453ae00000000"
        )

    def test_attack_change_input_address(self, client):
        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/0'/1/0"),
            # 2N1LGaGg836mqSQqiuUBLfcyGBhyZbremDX
            amount=123456789,
            prev_hash=bytes.fromhex(
                "20912f98ea3ed849042efed0fdac8cb4fc301961c5988cba56902d8ffb61c337"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
        )
        out1 = proto.TxOutputType(
            address="mhRx1CeVfaayqRwq5zgRQmD7W5aWBfD5mC",
            amount=12300000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address_n=parse_path("49'/1'/12'/1/0"),
            script_type=proto.OutputScriptType.PAYTOP2SHWITNESS,
            amount=123456789 - 11000 - 12300000,
        )

        # Test if the transaction can be signed normally
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
                client, "Testnet", [inp1], [out1, out2], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "0100000000010137c361fb8f2d9056ba8c98c5611930fcb48cacfdd0fe2e0449d83eea982f91200000000017160014d16b8c0680c61fc6ed2e407455715055e41052f5ffffffff02e0aebb00000000001976a91414fdede0ddc3be652a0ce1afbc1b509a55b6b94888ac3df39f060000000017a9142f98413cb83ff8b3eaf1926192e68973cbd68a3a8702473044022013cbce7c575337ca05dbe03b5920a0805b510cd8dfd3180bd7c5d01cec6439cd0220050001be4bcefb585caf973caae0ffec682347f2127cc22f26efd93ee54fd852012103e7bfe10708f715e8538c92d46ca50db6f657bbc455b7494e6a0303ccdb868b7900000000"
        )

        run_attack = True

        def attack_processor(msg):
            nonlocal run_attack

            if run_attack and msg.tx.inputs and msg.tx.inputs[0] == inp1:
                run_attack = False
                msg.tx.inputs[0].address_n[2] = H_(12)

            return msg

        # Now run the attack, must trigger the exception
        client.set_filter(proto.TxAck, attack_processor)
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
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.Failure(code=proto.FailureType.ProcessError),
                ]
            )
            with pytest.raises(CallException) as exc:
                btc.sign_tx(client, "Testnet", [inp1], [out1, out2], prev_txes=TX_API)
            assert exc.value.args[0] == proto.FailureType.ProcessError
            if client.features.model == "1":
                assert exc.value.args[1].endswith("Failed to compile input")
            else:
                assert exc.value.args[1].endswith(
                    "Transaction has changed during signing"
                )

    def test_send_multisig_csv_2(self, client):
        indices = [1, 2]
        nodes = [
            btc.get_public_node(client, parse_path("49'/1'/%d'" % index))
            for index in indices
        ]
        multisig = proto.MultisigRedeemScriptType(
            nodes=[deserialize(n.xpub) for n in nodes],
            address_n=[0, 1],  # non-hardened suffix for 49'/1'/1'/0/1
            signatures=[b"", b""],
            m=2,
            csv=(6 * 24 * 7),
        )
        for index in indices:
            assert (
                btc.get_address(
                    client,
                    "Regtest",
                    parse_path("49'/1'/%d'/0/1" % index),
                    show_display=False,
                    script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                    multisig=multisig,
                )
                == "2NG8sNrfkFuyfa6xWwG86PRHgrEw3JfDaXh"
            )

        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/1'/0/1"),
            # PREV TX 02000000000101ac88d3bae0c6da5d43360ed2f18c72913a966adcceed08c4fc8d9c29560bbd1000000000171600144c5e44c0abdd0db4881c1b43befedfc94f743918feffffff0200c999150000000017a914fb1731356772ce6c36b525d7989092c21e385bab871c1c6c1401000000160014d2701db46da7bed472617d675f8daf05ecd091ac02473044022075b184e6c1c60ce36a346206f940a14f6f60ee0c3c269d4d614e15e406016c0f022078f90d831426987824ddb3dc6c8adacb59b11c5801fcc05bad311fe491a6e3810121030d245f4b5271bc25fe3e92b350b24a7fb747f5f01f6b7f9c09e90a49b2ac6f5cc8000000
            prev_hash=bytes.fromhex(
                "2736dc3bcedd0b5e6db75ab9a12138b89c14ea82450c39e6a91d91bfbcf83a66"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=3_624_00000,
        )

        out1 = proto.TxOutputType(
            address="2Mwmx4XkCxPC43yTjscn9M8fjS15FAQTBsK",
            amount=3_623_90000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )

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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            signatures, _ = btc.sign_tx(
                client, "Regtest", [inp1], [out1], prev_txes=None
            )
            # store signature
            inp1.multisig.signatures[0] = signatures[0]
            # sign with server key
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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                client, "Regtest", [inp1], [out1], prev_txes=None
            )

        # TXID 031243d908cfbe2e3d59616c84807bf4dc7bdfeff308d35d6513b9aa3ad2d9dc
        assert (
            serialized_tx.hex()
            == "01000000000101663af8bcbf911da9e6390c4582ea149cb83821a1b95ab76d5e0bddce3bdc362700000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff01f0a199150000000017a91431b01a5aba3d310743a8d853b5530a229e51c5758703473044022052e9733211819469919fec115f1860775c4234df6d653ea3a4c87e40198a162b02207823bdd01b5bcc208f148b06019d3361a1e11fe9346cfee878cd0cdf490a74240147304402206e95e24506eb0535775dee0afec879f1959c7b5c43892104e03f7b7a5497dabb02203cc01fbc23d53823cc6ef58e66982ba9eaa0a386513176a92bc4890ef076861b0150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac00000000"
        )

    def test_send_multisig_csv_1(self, client):
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
                    "Regtest",
                    parse_path("49'/1'/%d'/0/1" % index),
                    show_display=False,
                    script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                    multisig=multisig,
                )
                == "2NG8sNrfkFuyfa6xWwG86PRHgrEw3JfDaXh"
            )

        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/1'/0/1"),
            # PREV TX 02000000000101ad2522d89729c7c199b69a62b6c7adeea3b3c69c28c1c79cecfeb822c76ca09500000000171600144c5e44c0abdd0db4881c1b43befedfc94f743918feffffff0200c999150000000017a914fb1731356772ce6c36b525d7989092c21e385bab879ca6e734000000001600146d4cab1414be71b22834b4216de02937278401b002473044022036e87034c040cf7319bae0496c7fd3855ffa30471eee8cc3ad7817d5357e56d80220118e7d37475e794c65ef247141946073ea024d72c98207e6b067351b4fab69410121030d245f4b5271bc25fe3e92b350b24a7fb747f5f01f6b7f9c09e90a49b2ac6f5c91010000
            prev_hash=bytes.fromhex(
                "852d296aa0ceccd41f6316431b9ba78b12de06d9697578c207e9666ab8a4daa2"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=3_624_00000,
            sequence=multisig.csv,  # MUST BE PRESENT!
        )

        out1 = proto.TxOutputType(
            address="2Mwmx4XkCxPC43yTjscn9M8fjS15FAQTBsK",
            amount=3_623_90000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )

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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                client,
                "Regtest",
                [inp1],
                [out1],
                prev_txes=None,
                details=proto.SignTx(version=2),
            )

        # TXID 3839bde4860662595364f20f18dc6cb42673f195f942775cc0bc5bf7e6acb91e
        assert (
            serialized_tx.hex()
            == "02000000000101a2daa4b86a66e907c2787569d906de128ba79b1b4316631fd4cccea06a292d8500000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1f003000001f0a199150000000017a91431b01a5aba3d310743a8d853b5530a229e51c57587024830450221008015291b73f26ac4bcc1580d27e4c498623c6a75195879a762d3d2bae99f9a2102204605542d9a9e4448698efede25e92caac2f5150e3dc56ffc008ab9839db9502b0150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac00000000"
        )

    def test_send_multisig_csv_2_testnet(self, client):
        indices = [1, 2]
        nodes = [
            btc.get_public_node(client, parse_path("49'/1'/%d'" % index))
            for index in indices
        ]
        multisig = proto.MultisigRedeemScriptType(
            nodes=[deserialize(n.xpub) for n in nodes],
            address_n=[0, 1],  # non-hardened suffix for 49'/1'/1'/0/1
            signatures=[b"", b""],
            m=2,
            csv=(6 * 24 * 7),
        )
        for index in indices:
            assert (
                btc.get_address(
                    client,
                    "Testnet",
                    parse_path("49'/1'/%d'/0/1" % index),
                    show_display=False,
                    script_type=proto.InputScriptType.SPENDP2SHWITNESS,
                    multisig=multisig,
                )
                == "2NG8sNrfkFuyfa6xWwG86PRHgrEw3JfDaXh"
            )

        inp1 = proto.TxInputType(
            address_n=parse_path("49'/1'/1'/0/1"),
            # PREV TX 0200000000010139cb1e2ac465944003be8208cf6c53a2e8764ca435f35855cff5eb0b534567860000000017160014c7be101d3093dfe09d912f6d02148371a145c442feffffff0240420f000000000017a914fb1731356772ce6c36b525d7989092c21e385bab87837111000000000016001473f0e0d4eb863e2499075dc2816647d33e6dcbab0247304402202ac37b2acfb171cb10d678c36448137b309361b23f14620666ad59e2278fbf5302200430cf8eec20d9508b3de4de0410d94fbbd9253df62d5a27f28c981e19275bdd0121025d0ae6920d50f77f5f3c2d4a065bdd1309becec4557a53e472bec563dc205683338a1800
            prev_hash=bytes.fromhex(
                "8925a4882af6f4209b6d7f6fa777c554bde706ddce90204a705b26421f662a37"
            ),
            prev_index=0,
            script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            multisig=multisig,
            amount=10_00000,
        )

        out1 = proto.TxOutputType(
            address="2N3iEJXZZXPWQJmTMe2YHLzWDPpBuA93n1P",
            amount=9_99000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )

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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            signatures, _ = btc.sign_tx(
                client, "Testnet", [inp1], [out1], prev_txes=None
            )
            # store signature
            inp1.multisig.signatures[0] = signatures[0]
            # sign with server key
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
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                client, "Testnet", [inp1], [out1], prev_txes=None
            )

        # TXID 0cc9159979949c2324907e6a9fb8afeb79be51e6fa5b65e4014eb03b38a1f3ba
        assert (
            serialized_tx.hex()
            == "01000000000101372a661f42265b704a2090cedd06e7bd54c577a76f7f6d9b20f4f62a88a4258900000000232200207b6de8dfee7092963c7c1576950ad68ee6accc9e1f56fcc6fb65d4eacee19ab1ffffffff01583e0f000000000017a91472ccc05a47677da539332a3cde25116f5a3beb7b8703483045022100961064a7f1ad62e03d5bd02e9ef1bd9e15da591f7359d69bb30808a817dec9aa02203c7d8c1de303a924a9030840ce5d902097ed1cff9ef2bdb7c7a8c13ec09577ce0147304402205663523c2f21936f8da078556ad6d7bf476d18014913cccf2245127b9b634253022034c97b0fd6b6168adf53a6f49e2171de40038f49b35b0207963f21ee15faeeb80150748c632102ec74358bd9ef1d1dab4261bef56b40b154e6790a0035b5caea0322404ad9b44dad6702f003b275682102b0aabdf00de32b7e9d6b3b1e30c25d9af664e1336c00441aee0affc49757cf0aac00000000"
        )
