#!/usr/bin/env python3
"""
Convert a BIP39 mnemonic into Taproot (BIP86) descriptors ready to import
into Bitcoin Core, with their checksums already computed.

Uses only the Python standard library: nothing to install, which makes it
easy to run on an offline machine.

Usage:
    python3 bip39_to_taproot.py            # mainnet
    python3 bip39_to_taproot.py --testnet  # testnet / signet / regtest
    python3 bip39_to_taproot.py --wordlist english.txt   # validate the mnemonic
    python3 bip39_to_taproot.py --timestamp 2023-05-14   # rescan from that date

ALWAYS RUN IT ON AN OFFLINE MACHINE. The output contains your master
private key: anyone who sees it controls your funds.
"""

import argparse
import getpass
import hashlib
import hmac
import json
import sys
import unicodedata
from datetime import datetime, timezone

GENESIS_TIMESTAMP = 1231006505  # 2009-01-03, genesis block

# ---------------------------------------------------------------------------
# BIP39: mnemonic -> seed
# ---------------------------------------------------------------------------

def normalize(text: str) -> str:
    return unicodedata.normalize("NFKD", text)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic = normalize(" ".join(mnemonic.split()))
    salt = normalize("mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), salt.encode(), 2048)


def validate_mnemonic(mnemonic: str, wordlist_path: str) -> None:
    """Check that every word exists and that the BIP39 checksum matches."""
    with open(wordlist_path, encoding="utf-8") as f:
        wordlist = [normalize(w.strip()) for w in f if w.strip()]
    if len(wordlist) != 2048:
        sys.exit("The wordlist must contain 2048 entries.")
    word_index = {w: i for i, w in enumerate(wordlist)}

    words = normalize(mnemonic).split()
    if len(words) not in (12, 15, 18, 21, 24):
        sys.exit(f"Invalid number of words: {len(words)}")
    unknown = [w for w in words if w not in word_index]
    if unknown:
        sys.exit(f"Words not in the BIP39 wordlist: {unknown}")

    bits = "".join(format(word_index[w], "011b") for w in words)
    checksum_len = len(bits) // 33
    entropy_bits, checksum_bits = bits[:-checksum_len], bits[-checksum_len:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    expected = format(hashlib.sha256(entropy).digest()[0], "08b")[:checksum_len]
    if checksum_bits != expected:
        sys.exit("Invalid BIP39 checksum. Check the words.")


# ---------------------------------------------------------------------------
# BIP32: seed -> master xprv
# ---------------------------------------------------------------------------

SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload: bytes) -> str:
    payload += hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload, "big")
    result = ""
    while n:
        n, remainder = divmod(n, 58)
        result = BASE58_ALPHABET[remainder] + result
    leading_zeros = len(payload) - len(payload.lstrip(b"\x00"))
    return "1" * leading_zeros + result


def seed_to_xprv(seed: bytes, testnet: bool = False) -> str:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_key, chain_code = digest[:32], digest[32:]
    k = int.from_bytes(private_key, "big")
    if k == 0 or k >= SECP256K1_ORDER:
        sys.exit("Invalid seed (astronomically unlikely). Use another mnemonic.")
    version = bytes.fromhex("04358394" if testnet else "0488ade4")
    payload = (
        version
        + b"\x00"                # depth 0
        + b"\x00\x00\x00\x00"    # parent fingerprint
        + b"\x00\x00\x00\x00"    # child index
        + chain_code
        + b"\x00" + private_key
    )
    return base58check_encode(payload)


# ---------------------------------------------------------------------------
# Descriptor checksum (same algorithm as Bitcoin Core, BIP380)
# ---------------------------------------------------------------------------

INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def _polymod(c: int, val: int) -> int:
    c0 = c >> 35
    c = ((c & 0x7FFFFFFFF) << 5) ^ val
    for i in range(5):
        if (c0 >> i) & 1:
            c ^= GENERATOR[i]
    return c


def descriptor_checksum(descriptor: str) -> str:
    c, cls, cls_count = 1, 0, 0
    for ch in descriptor:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            raise ValueError(f"Invalid character in descriptor: {ch!r}")
        c = _polymod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        cls_count += 1
        if cls_count == 3:
            c = _polymod(c, cls)
            cls, cls_count = 0, 0
    if cls_count > 0:
        c = _polymod(c, cls)
    for _ in range(8):
        c = _polymod(c, 0)
    c ^= 1
    return "".join(CHECKSUM_CHARSET[(c >> (5 * (7 - i))) & 31] for i in range(8))


def add_checksum(descriptor: str) -> str:
    return f"{descriptor}#{descriptor_checksum(descriptor)}"


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def parse_timestamp(value: str):
    """Accept "now", a YYYY-MM-DD date (00:00 UTC) or a Unix timestamp."""
    if value == "now":
        return "now"
    if value.isdigit():
        ts = int(value)
    else:
        try:
            date = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f'"{value}" is not valid. Use "now", YYYY-MM-DD or a Unix timestamp.'
            )
        ts = int(date.timestamp())
    if ts > datetime.now(timezone.utc).timestamp():
        raise argparse.ArgumentTypeError("The date cannot be in the future.")
    if ts < GENESIS_TIMESTAMP:
        raise argparse.ArgumentTypeError("The date is before the genesis block (2009-01-03).")
    return ts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--testnet", action="store_true",
                        help="Generate tprv and path 86h/1h/0h (testnet, signet, regtest)")
    parser.add_argument("--account", type=int, default=0,
                        help="BIP86 account number (default 0)")
    parser.add_argument("--timestamp", default="now", type=parse_timestamp,
                        help='"now" for a new seed, or the date of first use: '
                             'YYYY-MM-DD (taken as 00:00 UTC) or a Unix timestamp')
    parser.add_argument("--wordlist",
                        help="Path to the BIP39 wordlist (english.txt) to validate the mnemonic")
    args = parser.parse_args()

    # getpass does not echo what you type
    mnemonic = getpass.getpass("BIP39 mnemonic (hidden): ").strip().lower()
    passphrase = getpass.getpass("BIP39 passphrase (press Enter if none): ")
    if passphrase:
        if getpass.getpass("Repeat the passphrase: ") != passphrase:
            sys.exit("Passphrases do not match.")

    if args.wordlist:
        validate_mnemonic(mnemonic, args.wordlist)
        print("Valid mnemonic (words and BIP39 checksum OK).\n")
    else:
        print("Warning: without --wordlist the mnemonic is not validated. "
              "A misspelled word produces a different wallet.\n")

    xprv = seed_to_xprv(mnemonic_to_seed(mnemonic, passphrase), args.testnet)
    coin_type = "1h" if args.testnet else "0h"
    path = f"86h/{coin_type}/{args.account}h"

    receive_desc = add_checksum(f"tr({xprv}/{path}/0/*)")
    change_desc = add_checksum(f"tr({xprv}/{path}/1/*)")

    ts = args.timestamp
    if ts != "now":
        date_str = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"Rescan from: {date_str} (timestamp {ts})")
    import_request = [
        {"desc": receive_desc, "timestamp": ts, "active": True, "internal": False},
        {"desc": change_desc, "timestamp": ts, "active": True, "internal": True},
    ]

    display_path = path.replace("h", "'")
    print(f"Derivation path: m/{display_path}")
    print(f"\nReceive descriptor:\n{receive_desc}")
    print(f"\nChange descriptor:\n{change_desc}")
    print("\nBitcoin Core command:")
    print(f"bitcoin-cli -rpcwallet=my_wallet importdescriptors "
          f"'{json.dumps(import_request)}'")


if __name__ == "__main__":
    main()
