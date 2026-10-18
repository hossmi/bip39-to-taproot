# bip39-to-taproot
Convert a BIP39 mnemonic into Taproot (BIP86) descriptors ready to import
into Bitcoin Core, with their checksums already computed.

## Usage
Uses only the Python standard library: nothing to install, which makes it
easy to run on an offline machine.

```
    python3 bip39_to_taproot.py                         # mainnet
    python3 bip39_to_taproot.py --testnet               # testnet / signet / regtest
    python3 bip39_to_taproot.py --wordlist english.txt  # validate the mnemonic
    python3 bip39_to_taproot.py --timestamp 2023-05-14  # rescan from that date
```

ALWAYS RUN IT ON AN OFFLINE MACHINE. The output contains your master
private key: anyone who sees it controls your funds.

## Useful links
The english.txt can be downloaded from [bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039) repository or this [direct file link](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).