from trezor.crypto.hashlib import sha256
from trezor.messages import FailureType, InputScriptType
from trezor.messages.SignTx import SignTx
from trezor.messages.TxInputType import TxInputType
from trezor.messages.TxOutputBinType import TxOutputBinType
from trezor.utils import HashWriter, ensure

from apps.common.coininfo import CoinInfo
from apps.wallet.sign_tx.multisig import multisig_get_pubkeys
from apps.wallet.sign_tx.scripts import output_script_multisig, output_script_p2pkh
from apps.wallet.sign_tx.writers import (
    get_tx_hash,
    write_bytes,
    write_bytes_reversed,
    write_tx_output,
    write_uint32,
    write_uint64,
    write_varint,
)


class Bip143Error(ValueError):
    pass


class Bip143:
    def __init__(self):
        self.h_prevouts = HashWriter(sha256())
        self.h_sequence = HashWriter(sha256())
        self.h_issuance = HashWriter(sha256())
        self.h_outputs = HashWriter(sha256())

    def add_prevouts(self, txi: TxInputType):
        write_bytes_reversed(self.h_prevouts, txi.prev_hash)
        write_uint32(self.h_prevouts, txi.prev_index)

    def add_sequence(self, txi: TxInputType):
        write_uint32(self.h_sequence, txi.sequence)

    def add_issuance(self, txi: TxInputType):
        # TODO: handle issuance properly, ignore for now
        issuance = b""
        write_varint(self.h_issuance, len(issuance))
        write_bytes(self.h_issuance, issuance)

    def add_output(self, txo_bin: TxOutputBinType, confidential=None):
        write_tx_output(self.h_outputs, txo_bin, confidential=confidential)

    def get_prevouts_hash(self, coin: CoinInfo) -> bytes:
        return get_tx_hash(self.h_prevouts, double=coin.sign_hash_double)

    def get_sequence_hash(self, coin: CoinInfo) -> bytes:
        return get_tx_hash(self.h_sequence, double=coin.sign_hash_double)

    def get_issuance_hash(self, coin: CoinInfo) -> bytes:
        return get_tx_hash(self.h_issuance, double=coin.sign_hash_double)

    def get_outputs_hash(self, coin: CoinInfo) -> bytes:
        return get_tx_hash(self.h_outputs, double=coin.sign_hash_double)

    def preimage_hash(
        self,
        coin: CoinInfo,
        tx: SignTx,
        txi: TxInputType,
        pubkeyhash: bytes,
        sighash: int,
        confidential=None,
    ) -> bytes:
        h_preimage = HashWriter(sha256())

        ensure(not tx.overwintered)

        write_uint32(h_preimage, tx.version)  # nVersion
        write_bytes(h_preimage, self.get_prevouts_hash(coin))  # hashPrevouts
        write_bytes(h_preimage, self.get_sequence_hash(coin))  # hashSequence
        if coin.confidential_assets:
            write_bytes(h_preimage, self.get_issuance_hash(coin))  # hashIssuance

        write_bytes_reversed(h_preimage, txi.prev_hash)  # outpoint
        write_uint32(h_preimage, txi.prev_index)  # outpoint

        script_code = self.derive_script_code(txi, pubkeyhash)  # scriptCode
        write_varint(h_preimage, len(script_code))
        write_bytes(h_preimage, script_code)

        if coin.confidential_assets:
            assert txi.confidential is not None
            assert confidential is not None
            assert confidential.amount == txi.amount
            assert confidential.asset == txi.confidential.asset
            confidential.serialize_amount(h_preimage)
        else:
            write_uint64(h_preimage, txi.amount)
        write_uint32(h_preimage, txi.sequence)  # nSequence
        write_bytes(h_preimage, self.get_outputs_hash(coin))  # hashOutputs
        write_uint32(h_preimage, tx.lock_time)  # nLockTime
        write_uint32(h_preimage, sighash)  # nHashType

        return get_tx_hash(h_preimage, double=coin.sign_hash_double)

    # see https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    # item 5 for details
    def derive_script_code(self, txi: TxInputType, pubkeyhash: bytes) -> bytearray:

        if txi.multisig:
            return output_script_multisig(
                multisig_get_pubkeys(txi.multisig), txi.multisig.m
            )

        p2pkh = (
            txi.script_type == InputScriptType.SPENDWITNESS
            or txi.script_type == InputScriptType.SPENDP2SHWITNESS
            or txi.script_type == InputScriptType.SPENDADDRESS
        )
        if p2pkh:
            # for p2wpkh in p2sh or native p2wpkh
            # the scriptCode is a classic p2pkh
            return output_script_p2pkh(pubkeyhash)

        else:
            raise Bip143Error(
                FailureType.DataError,
                "Unknown input script type for bip143 script code",
            )
