from trezor.crypto import base58, bech32, hashlib, hmac
from trezor.crypto.curve import secp256k1_zkp
from trezor.messages import InputScriptType
from trezor.messages.Address import Address

from apps.common import HARDENED, address_type, coins, paths
from apps.common.layout import address_n_to_str, show_address, show_qr
from apps.wallet.sign_tx import addresses, scripts

from ubinascii import hexlify as h

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

    print('seed:', h(keychain.seed))

    pubkey = keychain.derive(msg.address_n, coin.curve_name).public_key()
    print('script pubkey:', h(pubkey), '@', address_n_to_str(msg.address_n))

    address_builders = {
        InputScriptType.SPENDADDRESS: address_pkh,
        InputScriptType.SPENDP2SHWITNESS: address_p2wpkh_in_p2sh,
        # TODO: add support to blech32 addresses (not the same as bech32...)
    }
    address_builder = address_builders.get(msg.script_type)
    if not address_builder:
        raise AddressError(FailureType.ProcessError, "Invalid script type")

    address = address_builder(pubkey=pubkey, coin=coin, keychain=keychain)

    if msg.show_display:
        desc = address_n_to_str(msg.address_n)
        while True:
            if await show_address(ctx, address=address, desc=desc):
                break
            if await show_qr(ctx, address=address, desc=desc):
                break

    return Address(address=address)


def derive_public_blinding_key(keychain, script: bytes):
    # TODO: I guess it should be defined in a separate SLIP...
    derivation_key = keychain.derive([HARDENED | 77]).private_key()
    print('blinding derivation key:', h(derivation_key))
    blinding_private_key = hmac.new(
        key=derivation_key, msg=script, digestmod=hashlib.sha256
    ).digest()
    print('blinding private key:', h(blinding_private_key))
    pubkey = secp256k1_zkp.Context().publickey(blinding_private_key)
    print('blinding public key:', h(pubkey))
    return pubkey


# TODO: consider adding to CoinInfo (see https://github.com/ElementsProject/elements/blob/master/src/key_io.cpp)
BLINDED_ADDRESS_PREFIX = bytes([4])


def address_pkh(pubkey: bytes, coin: CoinInfo, keychain) -> str:
    script_hash = coin.script_hash(pubkey)
    script = scripts.output_script_p2pkh(pubkey)

    prefix = BLINDED_ADDRESS_PREFIX + address_type.tobytes(coin.address_type)
    blinding_pubkey = derive_public_blinding_key(script=script, keychain=keychain)
    data = prefix + blinding_pubkey + script_hash
    print('address_pkh data:', h(data))
    return base58.encode_check(data, coin.b58_hash)


def address_p2wpkh_in_p2sh(pubkey: bytes, coin: CoinInfo, keychain) -> str:
    pubkey_hash = addresses.ecdsa_hash_pubkey(pubkey, coin)
    redeem_script = scripts.output_script_native_p2wpkh_or_p2wsh(pubkey_hash)
    redeem_script_hash = coin.script_hash(redeem_script)

    prefix = BLINDED_ADDRESS_PREFIX + address_type.tobytes(coin.address_type_p2sh)
    blinding_pubkey = derive_public_blinding_key(
        script=redeem_script, keychain=keychain
    )
    data = prefix + blinding_pubkey + redeem_script_hash
    print('address_p2wpkh_in_p2sh data:', h(data))
    return base58.encode_check(data, coin.b58_hash)
