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

from trezorlib import liquid, messages as proto
from trezorlib.tools import parse_path

from .common import TrezorTest


@pytest.mark.liquid
class TestMsgLiquidGetBlindedAddress(TrezorTest):
    def test_elements_blinded_address(self):
        self.setup_mnemonic_nopin_nopassphrase()

        assert (
            liquid.get_blinded_address(
                self.client,
                n=parse_path("m/44'/1'/0'/0/0"),
                coin_name="Elements",
                script_type=proto.InputScriptType.SPENDADDRESS,
            )
            == "CTEqHgzv7DQ4BWMLNajmNA5VQ8YikPPQ4EkretjtWsBQ7pNhFdDPFMHBfrmaBwh9ZLTrtcZUYJtq3pbJ"
        )

        assert (
            liquid.get_blinded_address(
                self.client,
                n=parse_path("m/49'/1'/0'/0/0"),
                coin_name="Elements",
                script_type=proto.InputScriptType.SPENDP2SHWITNESS,
            )
            == "AzpvjySCSPyqppx1FFTFWZF9X7gJmxNfXv1z3W8mQgZYHw9qucPJhgXJjjBzLr3h2ejDTjpYUG2G86kH"
        )
