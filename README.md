# bip39-to-taproot

Convert a BIP39 mnemonic (12–24 words) into **Taproot (BIP86) output descriptors** that Bitcoin Core can import, with descriptor checksums already computed.

Bitcoin Core does not support BIP39 mnemonics, but its descriptor wallets accept an extended private key (`xprv`). This script derives that key from your mnemonic, builds the receive and change descriptors, and prints a ready-to-run `importdescriptors` command. You keep a portable backup (the words), and Bitcoin Core can still use the wallet.

> [!WARNING]
> **Run this script only on an offline machine.** The output contains your master private key. Anyone who sees it controls your funds. Do not save the output to a file, paste it into an online machine, or take screenshots of it.

## Features

- **Standard library only:** no `pip install` needed, so it's easy to audit and to move to an air-gapped computer.
- **Hidden input:** the mnemonic and passphrase are not shown on screen as you type them.
- **Optional BIP39 passphrase** (the "25th word"), entered twice to avoid typos.
- **Optional mnemonic validation** against the official wordlist, including the BIP39 checksum.
- **Descriptor checksums** computed with the same algorithm as Bitcoin Core (BIP380), so `getdescriptorinfo` isn't needed.
- **Rescan date** given as `YYYY-MM-DD`, as a Unix timestamp, or as `now`.
- **Mainnet and testnet/signet/regtest** support, plus multiple BIP86 accounts.

## Requirements

- Python 3.8 or newer
- Bitcoin Core with descriptor wallets (the default since v23)

## Usage

```
python3 bip39-to-taproot.py [-h] [--testnet] [--account ACCOUNT]
                            [--timestamp TIMESTAMP] [--wordlist WORDLIST]
```

| Option | Default | Description |
|---|---|---|
| `-h`, `--help` | | Show the help message and exit. |
| `--testnet` | off | Generate a `tprv` and the path `86h/1h/…`, for testnet, signet and regtest. |
| `--account N` | `0` | BIP86 account number (see [Accounts](#accounts)). |
| `--timestamp T` | `now` | When Bitcoin Core should start rescanning: `now`, a date (`YYYY-MM-DD`, read as 00:00 UTC), or a Unix timestamp. |
| `--wordlist FILE` | | Path to the BIP39 English wordlist. When given, the script checks the words and the BIP39 checksum before deriving anything. |

The script prompts for the mnemonic and the passphrase after it starts. Press Enter at the passphrase prompt if you don't use one.

## Examples

**New wallet (nothing to rescan):**

```bash
python3 bip39-to-taproot.py
```

**Existing mnemonic first used in May 2023.** Bitcoin Core rescans the blockchain from that date:

```bash
python3 bip39-to-taproot.py --timestamp 2023-05-14
```

**Validate the mnemonic before deriving (recommended).** The wordlist is not included in this repository. Download it from the [bip-0039 folder](https://github.com/bitcoin/bips/tree/master/bip-0039) of the BIPs repository *before* disconnecting the machine:

```bash
curl -O https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
python3 bip39-to-taproot.py --wordlist english.txt
```

**Dry run on testnet/signet before using real funds:**

```bash
python3 bip39-to-taproot.py --testnet
```

**Second account from the same mnemonic:**

```bash
python3 bip39-to-taproot.py --account 1 --timestamp 2024-01-01
```

### Sample output

This uses the public test mnemonic `abandon abandon … about` with no passphrase. **Never send funds to it.**

```
Warning: without --wordlist the mnemonic is not validated. A misspelled word produces a different wallet.

Rescan from: 2023-05-14 00:00 UTC (timestamp 1684022400)
Derivation path: m/86'/0'/0'

Receive descriptor:
tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86h/0h/0h/0/*)#qqzyw9t6

Change descriptor:
tr(xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu/86h/0h/0h/1/*)#3589nsmz

Bitcoin Core command:
bitcoin-cli -rpcwallet=my_wallet importdescriptors '[{"desc": "tr(...)#qqzyw9t6", "timestamp": 1684022400, "active": true, "internal": false}, {"desc": "tr(...)#3589nsmz", "timestamp": 1684022400, "active": true, "internal": true}]'
```

## Importing into Bitcoin Core

1. **Create a blank descriptor wallet** (no keys of its own):

   ```bash
   bitcoin-cli createwallet "my_wallet" false true
   ```

2. **Run the command the script printed.** Change `my_wallet` if you picked a different name. If you used a past `--timestamp`, the rescan can take a while.

3. **Verify the import.** Request the first address and compare it with another BIP39 wallet (Sparrow, for example) restored from the same mnemonic, passphrase and script type (Taproot, P2TR):

   ```bash
   bitcoin-cli -rpcwallet=my_wallet getnewaddress "" bech32m
   ```

   With the test mnemonic above, the first address must be `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr`.

4. **Clear your shell history**, since the import command contains the `xprv`:

   ```bash
   history -c   # bash; or prefix the command with a space if HISTCONTROL=ignorespace
   ```

## What to back up

To restore the wallet anywhere, in Bitcoin Core or in any BIP39 wallet, you need:

- the **mnemonic** (12–24 words);
- the **passphrase**, if you used one. Without it, the funds can't be recovered;
- the **derivation path** `m/86'/0'/N'`, which also says the wallet is Taproot, together with the **account number** if it isn't 0.

## Accounts

The account number lets you derive several independent wallets from one mnemonic:

```
m / 86' / 0' / 0' / 0 / 5
     │     │    │    │   └─ address index
     │     │    │    └───── 0 = receive, 1 = change
     │     │    └────────── account
     │     └─────────────── coin type (0 = bitcoin, 1 = testnet)
     └───────────────────── purpose (86 = Taproot)
```

Each account has its own addresses and balance. Two things to keep in mind:

- **Most wallets scan only account 0 by default.** If you use another account, write it down next to your words.
- **The separation is for bookkeeping only, not security.** The descriptors contain the *root* `xprv`, so a Bitcoin Core wallet holding account 1 can also derive every other account.

Unless you have a specific reason to separate funds, keep the default (`0`).

## How it works

1. **BIP39:** mnemonic + passphrase → 64-byte seed (PBKDF2-HMAC-SHA512, 2048 iterations).
2. **BIP32:** seed → master extended private key (`xprv` / `tprv`).
3. **BIP86 / BIP386:** build `tr(xprv/86h/0h/Nh/0/*)` for receiving and `…/1/*` for change. Bitcoin Core derives the child keys itself.
4. **BIP380:** append the descriptor checksum.

## Testing

The implementation is checked against the official test vectors:

```bash
python3 -c "
import importlib.util as u
spec = u.spec_from_file_location('m', 'bip39-to-taproot.py')
m = u.module_from_spec(spec); spec.loader.exec_module(m)
seed = m.mnemonic_to_seed('abandon ' * 11 + 'about', 'TREZOR')
assert m.seed_to_xprv(seed) == 'xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF'
assert m.descriptor_checksum('raw(deadbeef)') == '89f8spxm'
print('OK')
"
```

## Security checklist

- [ ] The machine has no network connection while the script runs.
- [ ] The mnemonic was generated offline, never on a website.
- [ ] You verified the first address against an independent wallet.
- [ ] You cleared your shell history and terminal scrollback afterwards.
- [ ] Your backup includes the passphrase (if any) and the derivation path.

## References

- [BIP39: Mnemonic code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32: Hierarchical deterministic wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP86: Key derivation for single-key P2TR outputs](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
- [BIP380: Output script descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
- [Bitcoin Core descriptors documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)

## License

[MIT](LICENSE) © 2026 Pablo Jimena

## Disclaimer

This software is provided as is, without warranty of any kind. You are solely responsible for the security of your keys and funds. Test on testnet or signet first.
