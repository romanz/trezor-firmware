from trezor.crypto import base58, bech32, cashaddr
from trezor.messages import InputScriptType
from trezor.messages.Address import Address

from apps.common import HARDENED, address_type, coins, paths
from apps.common.layout import address_n_to_str, show_address, show_qr
from apps.wallet.sign_tx import addresses, scripts


async def get_blinded_address(ctx, msg, keychain):
    coin = coins.by_name(msg.coin_name)

    await paths.validate_path(
        ctx,
        addresses.validate_full_path,
        keychain,
        msg.address_n,
        coin.curve_name,
        coin=coin,
        script_type=msg.script_type,
    )

    public_key = keychain.derive(msg.address_n, coin.curve_name).public_key()
    # TODO: better derivation (i.e. new SLIP)
    blinding_key = keychain.derive(msg.address_n, coin.curve_name).public_key()

    address_builders = {
        InputScriptType.SPENDADDRESS: address_pkh,
        InputScriptType.SPENDP2SHWITNESS: address_p2wpkh_in_p2sh,
    }
    address_builder = address_builders.get(msg.script_type)
    if not address_builder:
        raise AddressError(FailureType.ProcessError, "Invalid script type")

    return Address(
        address=address_builder(
            public_key=public_key, blinding_key=blinding_key, coin=coin
        )
    )


BLINDED_ADDRESS_PREFIX = b"\x04"  # TODO: take from CoinInfo


def address_pkh(public_key: bytes, blinding_key: bytes, coin: CoinInfo) -> str:
    script_hash = coin.script_hash(public_key)
    prefix = BLINDED_ADDRESS_PREFIX + address_type.tobytes(coin.address_type)
    return base58.encode_check(prefix + blinding_key + script_hash, coin.b58_hash)


def address_p2wpkh_in_p2sh(
    public_key: bytes, blinding_key: bytes, coin: CoinInfo
) -> str:
    pubkey_hash = addresses.ecdsa_hash_pubkey(public_key, coin)
    redeem_script = scripts.output_script_native_p2wpkh_or_p2wsh(pubkey_hash)
    redeem_script_hash = coin.script_hash(redeem_script)
    prefix = BLINDED_ADDRESS_PREFIX + address_type.tobytes(coin.address_type_p2sh)
    return base58.encode_check(
        prefix + blinding_key + redeem_script_hash, coin.b58_hash
    )
