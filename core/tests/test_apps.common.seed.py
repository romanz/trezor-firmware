from common import *
from apps.common import HARDENED, storage, mnemonic, coins
from apps.common.seed import Keychain, Slip21Node, _path_hardened, derive_slip21_node_without_passphrase, derive_blinding_public_key
from apps.wallet.sign_tx import addresses
from trezor import wire
from trezor.crypto import bip32, bip39


class TestKeychain(unittest.TestCase):

    def test_validate_path(self):
        n = [
            ["ed25519", 44 | HARDENED, 134 | HARDENED],
            ["secp256k1", 44 | HARDENED, 11 | HARDENED],
        ]
        k = Keychain(b"", n)

        correct = (
            ([44 | HARDENED, 134 | HARDENED], "ed25519"),
            ([44 | HARDENED, 11 | HARDENED], "secp256k1"),
            ([44 | HARDENED, 11 | HARDENED, 12], "secp256k1"),
        )
        for c in correct:
            self.assertEqual(None, k.validate_path(*c))

        fails = [
            ([44 | HARDENED, 134], "ed25519"),  # path does not match
            ([44 | HARDENED, 134], "secp256k1"),  # curve and path does not match
            ([44 | HARDENED, 134 | HARDENED], "nist256p"),  # curve not included
            ([44, 134], "ed25519"),  # path does not match (non-hardened items)
            ([44 | HARDENED, 134 | HARDENED, 123], "ed25519"),  # non-hardened item in ed25519
            ([44 | HARDENED, 13 | HARDENED], "secp256k1"),  # invalid second item
        ]
        for f in fails:
            with self.assertRaises(wire.DataError):
                k.validate_path(*f)

    def test_validate_path_special_ed25519(self):
        n = [
            ["ed25519-keccak", 44 | HARDENED, 134 | HARDENED],
        ]
        k = Keychain(b"", n)

        correct = (
            ([44 | HARDENED, 134 | HARDENED], "ed25519-keccak"),
        )
        for c in correct:
            self.assertEqual(None, k.validate_path(*c))

        fails = [
            ([44 | HARDENED, 134 | HARDENED, 1], "ed25519-keccak"),
        ]
        for f in fails:
            with self.assertRaises(wire.DataError):
                k.validate_path(*f)

    def test_validate_path_empty_namespace(self):
        k = Keychain(b"", [["secp256k1"]])
        correct = (
            ([], "secp256k1"),
            ([1, 2, 3, 4], "secp256k1"),
            ([44 | HARDENED, 11 | HARDENED], "secp256k1"),
            ([44 | HARDENED, 11 | HARDENED, 12], "secp256k1"),
        )
        for c in correct:
            self.assertEqual(None, k.validate_path(*c))

        with self.assertRaises(wire.DataError):
            k.validate_path([1, 2, 3, 4], "ed25519")
            k.validate_path([], "ed25519")

    def test_path_hardened(self):
        self.assertTrue(_path_hardened([44 | HARDENED, 1 | HARDENED, 0 | HARDENED]))
        self.assertTrue(_path_hardened([0 | HARDENED, ]))

        self.assertFalse(_path_hardened([44, 44 | HARDENED, 0 | HARDENED]))
        self.assertFalse(_path_hardened([0, ]))
        self.assertFalse(_path_hardened([44 | HARDENED, 1 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0]))

    def test_slip21(self):
        seed = bip39.seed(' '.join(['all'] * 12), '')
        node1 = Slip21Node(seed)
        node2 = node1.clone()

        # Key(m)
        self.assertEqual(node1.key(), unhexlify(b"dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756"))

        # Key(m/"SLIP-0021")
        node1.derive_path([b"SLIP-0021"])
        self.assertEqual(node1.key(), unhexlify(b"1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d"))

        # Key(m/"SLIP-0021"/"Master encryption key")
        node1.derive_path([b"Master encryption key"])
        self.assertEqual(node1.key(), unhexlify(b"ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde"))

        # Key(m/"SLIP-0021"/"Authentication key")
        node2.derive_path([b"SLIP-0021", b"Authentication key"])
        self.assertEqual(node2.key(), unhexlify(b"47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6"))

    def test_slip77(self):
        seed = bip39.seed(' '.join(['all'] * 12), '')
        root = Slip21Node(seed=seed)
        self.assertEqual(root.key(), unhexlify("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756"))

        root.derive_path([b"SLIP-0077"])
        master_blinding_key = root.key()

        node = bip32.from_seed(seed, 'secp256k1')
        node.derive_path([44 | HARDENED, 1 | HARDENED, 0 | HARDENED, 0, 0])
        pubkey = node.public_key()
        coin = coins.by_name('Elements')
        def derive_blinding_pubkey(script):
            return derive_blinding_public_key(master_blinding_key=master_blinding_key, script=script)

        address = addresses.address_pkh(pubkey=pubkey, coin=coin,
                                        derive_blinding_pubkey=derive_blinding_pubkey)
        self.assertEqual(address, "CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ")


if __name__ == '__main__':
    unittest.main()
