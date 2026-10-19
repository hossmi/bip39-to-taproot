"""
Unit tests for bip39-to-taproot.py.

They use only Python's built-in `unittest` module, so the project stays
"standard library only". Run them from the project root folder:

    python -m unittest discover tests -v

(If you ever install pytest, `python -m pytest` runs these same tests.)

How a unittest test works:
  - Tests live in a class that inherits from unittest.TestCase.
  - Every method whose name starts with `test_` is one test.
  - Inside it you call the code and check the result with self.assertEqual,
    self.assertTrue, self.assertRaises, etc. A failed check = a failed test.

All mnemonics, seeds and keys below are PUBLIC test vectors. Never use them.
"""

import argparse
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "bip39-to-taproot.py"
WORDLIST_PATH = PROJECT_ROOT / "english.txt"

# The script's file name contains hyphens, so `import bip39-to-taproot` is not
# valid Python. Instead we load the file by its path and give it a module name.
_spec = importlib.util.spec_from_file_location("bip39_to_taproot", SCRIPT_PATH)
taproot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(taproot)


# english.txt is listed in .gitignore, so a fresh clone may not have it.
# Tests that need it are skipped (not failed) when it is missing.
needs_wordlist = unittest.skipUnless(
    WORDLIST_PATH.exists(), "english.txt not found in the project folder")

MNEMONIC_12 = "abandon " * 11 + "about"
MNEMONIC_24 = "abandon " * 23 + "art"


class TestMnemonicToSeed(unittest.TestCase):
    """Official BIP39 vectors (trezor/python-mnemonic vectors.json)."""

    def test_12_words_with_passphrase(self):
        seed = taproot.mnemonic_to_seed(MNEMONIC_12, "TREZOR")
        self.assertEqual(
            seed.hex(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")

    def test_24_words_with_passphrase(self):
        seed = taproot.mnemonic_to_seed(MNEMONIC_24, "TREZOR")
        self.assertEqual(
            seed.hex(),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
            "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8")

    def test_extra_spaces_are_ignored(self):
        messy = "  abandon  " + "abandon " * 10 + "\tabout \n"
        self.assertEqual(taproot.mnemonic_to_seed(messy),
                         taproot.mnemonic_to_seed(MNEMONIC_12))

    def test_passphrase_changes_the_seed(self):
        self.assertNotEqual(taproot.mnemonic_to_seed(MNEMONIC_12, ""),
                            taproot.mnemonic_to_seed(MNEMONIC_12, "x"))

    def test_unicode_passphrase_is_normalized(self):
        # "é" can be typed as one character or as "e" + accent. BIP39 requires
        # NFKD normalization so both spellings give the same wallet.
        composed = "café"
        decomposed = "café"
        self.assertEqual(taproot.mnemonic_to_seed(MNEMONIC_12, composed),
                         taproot.mnemonic_to_seed(MNEMONIC_12, decomposed))


class TestSeedToXprv(unittest.TestCase):

    def test_bip32_vector_1(self):
        # BIP32 test vector 1, chain m.
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(
            taproot.seed_to_xprv(seed),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")

    def test_bip39_vector_xprv(self):
        # BIP39 vector: the 12-word mnemonic with passphrase "TREZOR".
        seed = taproot.mnemonic_to_seed(MNEMONIC_12, "TREZOR")
        self.assertEqual(
            taproot.seed_to_xprv(seed),
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF")

    def test_bip86_vector_root_key(self):
        # BIP86 test vector: the 12-word mnemonic, no passphrase.
        seed = taproot.mnemonic_to_seed(MNEMONIC_12)
        self.assertEqual(
            taproot.seed_to_xprv(seed),
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")

    def test_testnet_key_starts_with_tprv(self):
        seed = taproot.mnemonic_to_seed(MNEMONIC_12)
        self.assertTrue(taproot.seed_to_xprv(seed, testnet=True).startswith("tprv"))

    def test_key_has_standard_length(self):
        seed = taproot.mnemonic_to_seed(MNEMONIC_12)
        self.assertEqual(len(taproot.seed_to_xprv(seed)), 111)


class TestBase58Check(unittest.TestCase):

    def test_leading_zero_bytes_become_ones(self):
        # Each leading 0x00 byte is written as "1" in Base58.
        self.assertTrue(taproot.base58check_encode(b"\x00\x00\x01").startswith("11"))

    def test_known_value(self):
        # Version byte 0x00 + 20 zero bytes = the well-known "burn" address.
        self.assertEqual(taproot.base58check_encode(b"\x00" * 21),
                         "1111111111111111111114oLvT2")


class TestDescriptorChecksum(unittest.TestCase):

    def test_known_checksum(self):
        # Example from Bitcoin Core's descriptor documentation.
        self.assertEqual(taproot.descriptor_checksum("raw(deadbeef)"), "89f8spxm")

    def test_add_checksum_appends_hash_and_8_chars(self):
        self.assertEqual(taproot.add_checksum("raw(deadbeef)"), "raw(deadbeef)#89f8spxm")

    def test_checksum_uses_only_allowed_characters(self):
        checksum = taproot.descriptor_checksum("tr(xpubABC/86h/0h/0h/0/*)")
        self.assertEqual(len(checksum), 8)
        self.assertTrue(all(c in taproot.CHECKSUM_CHARSET for c in checksum))

    def test_one_changed_character_changes_checksum(self):
        self.assertNotEqual(taproot.descriptor_checksum("raw(deadbeef)"),
                            taproot.descriptor_checksum("raw(deadbeee)"))

    def test_invalid_character_raises(self):
        with self.assertRaises(ValueError):
            taproot.descriptor_checksum("raw(é)")


@needs_wordlist
class TestValidateMnemonic(unittest.TestCase):
    """validate_mnemonic returns None when OK and calls sys.exit() otherwise.
    sys.exit() raises SystemExit, which assertRaises can catch."""

    def assertRejected(self, mnemonic, message, wordlist=WORDLIST_PATH):
        with self.assertRaises(SystemExit) as ctx:
            taproot.validate_mnemonic(mnemonic, str(wordlist))
        self.assertIn(message, str(ctx.exception.code))

    def test_valid_12_words(self):
        self.assertIsNone(taproot.validate_mnemonic(MNEMONIC_12, str(WORDLIST_PATH)))

    def test_valid_24_words(self):
        self.assertIsNone(taproot.validate_mnemonic(MNEMONIC_24, str(WORDLIST_PATH)))

    def test_valid_official_vector(self):
        mnemonic = ("legal winner thank year wave sausage worth useful legal "
                    "winner thank yellow")
        self.assertIsNone(taproot.validate_mnemonic(mnemonic, str(WORDLIST_PATH)))

    def test_wrong_checksum(self):
        self.assertRejected("abandon " * 12, "Invalid BIP39 checksum")

    def test_wrong_word_count(self):
        self.assertRejected("abandon " * 11, "Invalid number of words: 11")

    def test_misspelled_word(self):
        self.assertRejected("abandon " * 11 + "abuot", "not in the BIP39 wordlist")

    def test_wordlist_with_wrong_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            short = Path(tmp) / "short.txt"
            short.write_text("abandon\nability\n", encoding="utf-8")
            self.assertRejected(MNEMONIC_12, "2048 entries", wordlist=short)


class TestParseTimestamp(unittest.TestCase):

    def test_now(self):
        self.assertEqual(taproot.parse_timestamp("now"), "now")

    def test_date_is_midnight_utc(self):
        self.assertEqual(taproot.parse_timestamp("2023-05-14"), 1684022400)

    def test_unix_timestamp(self):
        self.assertEqual(taproot.parse_timestamp("1700000000"), 1700000000)

    def test_genesis_timestamp_is_allowed(self):
        self.assertEqual(taproot.parse_timestamp(str(taproot.GENESIS_TIMESTAMP)),
                         taproot.GENESIS_TIMESTAMP)

    def test_before_genesis_is_rejected(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            taproot.parse_timestamp("2008-12-31")

    def test_future_is_rejected(self):
        tomorrow = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%d")
        with self.assertRaises(argparse.ArgumentTypeError):
            taproot.parse_timestamp(tomorrow)

    def test_garbage_is_rejected(self):
        for value in ("yesterday", "14/05/2023", "2023-13-01", "-5"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    taproot.parse_timestamp(value)


class TestMain(unittest.TestCase):
    """End-to-end: run main() with fake command-line arguments and fake
    typed input, then check what it prints.

    mock.patch temporarily replaces something for the duration of a `with`
    block: here sys.argv (the command-line arguments) and getpass.getpass
    (the hidden prompt), so the test needs no keyboard.
    """

    def run_main(self, args, answers):
        out = io.StringIO()
        with mock.patch("sys.argv", ["bip39-to-taproot.py"] + args), \
             mock.patch.object(taproot.getpass, "getpass", side_effect=answers), \
             redirect_stdout(out):
            taproot.main()
        return out.getvalue()

    def import_request(self, output):
        # The last line is: bitcoin-cli ... importdescriptors '<json>'
        last = output.strip().splitlines()[-1]
        return json.loads(last.split("'", 1)[1].rsplit("'", 1)[0])

    def test_mainnet_descriptors(self):
        output = self.run_main([], [MNEMONIC_12, ""])
        xprv = taproot.seed_to_xprv(taproot.mnemonic_to_seed(MNEMONIC_12))
        receive, change = self.import_request(output)

        self.assertIn("Derivation path: m/86'/0'/0'", output)
        self.assertEqual(receive["desc"], taproot.add_checksum(f"tr({xprv}/86h/0h/0h/0/*)"))
        self.assertEqual(change["desc"], taproot.add_checksum(f"tr({xprv}/86h/0h/0h/1/*)"))
        self.assertFalse(receive["internal"])
        self.assertTrue(change["internal"])
        self.assertEqual(receive["timestamp"], "now")

    def test_testnet_account_and_timestamp(self):
        output = self.run_main(
            ["--testnet", "--account", "2", "--timestamp", "2023-05-14"],
            [MNEMONIC_12, ""])
        receive, _ = self.import_request(output)
        self.assertIn("Derivation path: m/86'/1'/2'", output)
        self.assertTrue(receive["desc"].startswith("tr(tprv"))
        self.assertIn("/86h/1h/2h/0/*)", receive["desc"])
        self.assertEqual(receive["timestamp"], 1684022400)
        self.assertIn("Rescan from: 2023-05-14 00:00 UTC", output)

    def test_passphrase_must_be_repeated_correctly(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_main([], [MNEMONIC_12, "secret", "secreT"])
        self.assertIn("do not match", str(ctx.exception.code))

    def test_passphrase_is_used(self):
        output = self.run_main([], [MNEMONIC_12, "TREZOR", "TREZOR"])
        xprv = taproot.seed_to_xprv(taproot.mnemonic_to_seed(MNEMONIC_12, "TREZOR"))
        self.assertIn(xprv, output)

    def test_mnemonic_is_lowercased(self):
        upper = self.run_main([], [MNEMONIC_12.upper(), ""])
        lower = self.run_main([], [MNEMONIC_12, ""])
        self.assertEqual(upper, lower)

    def test_warns_without_wordlist(self):
        output = self.run_main([], [MNEMONIC_12, ""])
        self.assertIn("not validated", output)

    @needs_wordlist
    def test_validates_with_wordlist(self):
        output = self.run_main(["--wordlist", str(WORDLIST_PATH)], [MNEMONIC_12, ""])
        self.assertIn("Valid mnemonic", output)

    @needs_wordlist
    def test_invalid_mnemonic_stops_before_printing_keys(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit):
            with redirect_stdout(out):
                self.run_main(["--wordlist", str(WORDLIST_PATH)], ["abandon " * 12, ""])
        self.assertNotIn("xprv", out.getvalue())


if __name__ == "__main__":
    unittest.main()
