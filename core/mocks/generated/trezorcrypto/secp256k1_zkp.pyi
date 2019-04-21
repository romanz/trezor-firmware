from typing import *


# extmod/modtrezorcrypto/modtrezorcrypto-secp256k1_zkp.h
class RangeProofConfig:
    """
    Range proof configuration.
    """

    def __init__(self, min_value: int, exponent: int, bits: int):
        """
        Initialize range proof configuration.
        """


# extmod/modtrezorcrypto/modtrezorcrypto-secp256k1_zkp.h
class Context:
    """
    Owns a secp256k1 context.
    Can be allocated once and re-used between subsequent operations.
    """

    def __init__(self) -> None:
        """
        Allocate and initialize secp256k1_zkp context object.
        """

    def __enter__(self) -> None:
        """
        Allocate and initialize secp256k1_context memory.
        """

    def __exit__(self, *args) -> None:
        """
        Erase and free secp256k1_context memory.
        """

    def size(self) -> int:
        """
        Return the size in bytes of the internal secp256k1_ctx_buf buffer.
        """

    def generate_secret(self) -> bytes:
        """
        Generate secret key.
        """

    def publickey(self, secret_key: bytes, compressed: bool = True) -> bytes:
        """
        Computes public key from secret key.
        """

    def sign(
        self, secret_key: bytes, digest: bytes, compressed: bool = True
    ) -> bytes:
        """
        Uses secret key to produce the signature of the digest.
        """

    def verify(
        self, public_key: bytes, signature: bytes, digest: bytes
    ) -> bool:
        """
        Uses public key to verify the signature of the digest.
        Returns True on success.
        """

    def verify_recover(self, signature: bytes, digest: bytes) -> bytes:
        """
        Uses signature of the digest to verify the digest and recover the public
        key. Returns public key on success, None if the signature is invalid.
        """

    def multiply(
        self, secret_key: bytes, public_key: bytes, compressed_result: bool =
        False
    ) -> bytes:
        """
        Multiplies point defined by public_key with scalar defined by
        secret_key. Useful for ECDH. The resulting point is serialized in
        compressed format if `compressed_result` is True.
        """

    def blind_generator(asset: bytes, blinding_factor: bytes) -> bytes:
        '''
        Generate blinded generator for the specified confidential asset.
        '''

    def pedersen_commit(self, value: long, blinding_factor: bytes, gen: bytes)
    -> bytes:
        '''
        Commit to specified integer value, using given 32-byte blinding factor.
        '''

    def balance_blinds(self, values: Tuple[long], value_blinds: bytearray,
                       asset_blinds: bytes, num_of_inputs: int):
        '''
        Balance value blinds (by updating value_blinds in-place).
        '''

    def verify_balance(self, commitments: Tuple[bytes], num_of_inputs: int)
        '''
        Verify that Pedersen commitments are balanced.
        '''

    def rangeproof_sign(self, config: RangeProofConfig, value: int,
                        commit: bytes, blind: bytes, nonce: bytes,
                        message: bytes, extra_commit: bytes,
                        gen: bytes, proof_buffer: bytearray) -> memoryview:
        '''
        Return a range proof for specified value (as a memoryview of the
        specified bytearray).
        '''

    def rangeproof_rewind(self, conf_value: bytes, conf_asset: bytes,
                          nonce: bytes, range_proof: bytes,
                          extra_commit: bytes, message: bytearray) ->
                          (value: long, blind: bytes):
        '''
        Rewind a range proof to get the value, blinding factor and message.
        '''

    def surjection_proof(self, output_asset: bytes, output_asset_blind: bytes,
                         input_assets: bytes, input_assets_blinds: bytes,
                         input_assets_len: int, random_seed32: bytes,
                         proof_buffer: bytearray) -> bytes:
        '''
        Generate a surjection proof for specified input assets.
        '''

    def verify_surjection_proof(
        self, proof: bytes, output_generator: bytes, input_generators:
        Tuple[bytes]
    ) -> bytes:
        '''
        Verify a surjection proof for specified blinded assets.
        '''

    def allocate_proof_buffer() -> bytearray
        '''
        Allocate a buffer, large enough for holding a range proof / reduced size
        surjection proof.
        '''
