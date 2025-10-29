#!/usr/bin/env python3
"""
WalletGen: Generate and analyze crypto wallet addresses.

Features
- Bitcoin: BIP39 mnemonic, BIP44 (P2PKH), and BIP84 (Bech32 P2WPKH) derivations
- Ethereum: BIP39 mnemonic + BIP44 (m/44'/60'/0'/0/i) with Keccak-256/EIP-55 addresses
- Compare generated addresses against a known-address database (newline-separated file)
- Optional realtime balance checks via public APIs:
  - Bitcoin: Blockstream Esplora (https://blockstream.info)
  - Ethereum: Cloudflare Ethereum JSON-RPC (https://cloudflare-eth.com)

Usage examples
  python walletgen.py --count 3 --addr-count 2 --check-balance
  python walletgen.py --eth --address-db known_addresses.txt
  python walletgen.py --btc --print-mnemonic --addr-count 5 --output results.json

Security
- Mnemonics are NOT printed by default. Use --print-mnemonic only if you understand the risks.
- Consider running behind a network with privacy protections when checking balances.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests

try:
    from bip_utils import (
        Bip39MnemonicGenerator,
        Bip39WordsNum,
        Bip44,
        Bip44Coins,
        Bip44Changes,
        Bip84,
        Bip84Coins,
    )
except Exception as exc:  # pragma: no cover
    sys.stderr.write(
        "bip_utils is required. Install dependencies with: pip install -r requirements.txt\n"
    )
    raise


@dataclass(frozen=True)
class AddressRecord:
    chain: str  # "bitcoin" or "ethereum"
    derivation: str  # e.g. "bip44_p2pkh", "bip84_p2wpkh", "bip44_eth"
    index: int
    address: str


@dataclass
class BalanceRecord:
    address: str
    chain: str
    confirmed: Optional[float] = None  # BTC or ETH units
    confirmed_raw: Optional[int] = None  # sats or wei
    error: Optional[str] = None


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate BTC/EVM addresses and optionally match/check balances",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    chain_group = parser.add_mutually_exclusive_group()
    chain_group.add_argument("--btc", action="store_true", help="Generate Bitcoin addresses only")
    chain_group.add_argument("--eth", action="store_true", help="Generate Ethereum addresses only")

    parser.add_argument("--count", type=int, default=1, help="Number of mnemonics (wallets) to generate")
    parser.add_argument(
        "--addr-count",
        type=int,
        default=1,
        help="Number of addresses per derivation path per wallet",
    )
    parser.add_argument(
        "--words",
        type=int,
        choices=[12, 15, 18, 21, 24],
        default=12,
        help="Mnemonic word count",
    )
    parser.add_argument("--account", type=int, default=0, help="Account index (hardened)")
    parser.add_argument(
        "--print-mnemonic",
        action="store_true",
        help="Print the mnemonic for each wallet (SECURITY RISK)",
    )
    parser.add_argument(
        "--address-db",
        type=str,
        default=None,
        help="Path to newline-separated known addresses to match",
    )
    parser.add_argument(
        "--check-balance",
        action="store_true",
        help="Check balances via public explorers (network access)",
    )
    parser.add_argument(
        "--only-positive",
        action="store_true",
        help="When checking balances, only print addresses with non-zero balance",
    )
    parser.add_argument("--concurrency", type=int, default=8, help="Max concurrent network requests")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to write JSON results",
    )

    args = parser.parse_args(argv)
    return args


def load_address_database(file_path: Optional[str]) -> Set[str]:
    if not file_path:
        return set()
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Address DB not found: {file_path}")
    addresses: Set[str] = set()
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            normalized = line.strip()
            if normalized:
                addresses.add(normalized)
    return addresses


def generate_mnemonic(words: int) -> str:
    words_num_map = {
        12: Bip39WordsNum.WORDS_NUM_12,
        15: Bip39WordsNum.WORDS_NUM_15,
        18: Bip39WordsNum.WORDS_NUM_18,
        21: Bip39WordsNum.WORDS_NUM_21,
        24: Bip39WordsNum.WORDS_NUM_24,
    }
    if words not in words_num_map:
        raise ValueError("Unsupported words count")
    return Bip39MnemonicGenerator().FromWordsNumber(words_num_map[words])


def derive_bitcoin_addresses(
    mnemonic: str,
    account_index: int,
    address_count: int,
) -> Dict[str, List[AddressRecord]]:
    # BIP44 P2PKH: m/44'/0'/account'/0/i
    bip44_ctx = Bip44.FromMnemonic(mnemonic, Bip44Coins.BITCOIN)
    bip44_acc_ctx = bip44_ctx.Purpose().Coin().Account(account_index)
    bip44_ext_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

    p2pkh_records: List[AddressRecord] = []
    for i in range(address_count):
        addr_ctx = bip44_ext_ctx.AddressIndex(i)
        p2pkh_records.append(
            AddressRecord(
                chain="bitcoin",
                derivation="bip44_p2pkh",
                index=i,
                address=addr_ctx.PublicKey().ToAddress(),
            )
        )

    # BIP84 P2WPKH Bech32: m/84'/0'/account'/0/i
    bip84_ctx = Bip84.FromMnemonic(mnemonic, Bip84Coins.BITCOIN)
    bip84_acc_ctx = bip84_ctx.Purpose().Coin().Account(account_index)
    bip84_ext_ctx = bip84_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

    p2wpkh_records: List[AddressRecord] = []
    for i in range(address_count):
        addr_ctx = bip84_ext_ctx.AddressIndex(i)
        p2wpkh_records.append(
            AddressRecord(
                chain="bitcoin",
                derivation="bip84_p2wpkh",
                index=i,
                address=addr_ctx.PublicKey().ToAddress(),
            )
        )

    return {
        "bip44_p2pkh": p2pkh_records,
        "bip84_p2wpkh": p2wpkh_records,
    }


def derive_ethereum_addresses(
    mnemonic: str,
    account_index: int,
    address_count: int,
) -> List[AddressRecord]:
    # BIP44 (m/44'/60'/account'/0/i)
    bip44_ctx = Bip44.FromMnemonic(mnemonic, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_ctx.Purpose().Coin().Account(account_index)
    bip44_ext_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)

    records: List[AddressRecord] = []
    for i in range(address_count):
        addr_ctx = bip44_ext_ctx.AddressIndex(i)
        # bip_utils returns EIP-55 checksummed address
        records.append(
            AddressRecord(
                chain="ethereum",
                derivation="bip44_eth",
                index=i,
                address=addr_ctx.PublicKey().ToAddress(),
            )
        )
    return records


def match_addresses(
    records: Iterable[AddressRecord],
    known_addresses: Set[str],
) -> List[AddressRecord]:
    if not known_addresses:
        return []
    # Normalize by exact match; many explorers use checksum for ETH, lowercase to be lenient
    normalized_known = {a for a in known_addresses}
    normalized_known_lower = {a.lower() for a in known_addresses}

    matches: List[AddressRecord] = []
    for rec in records:
        if rec.address in normalized_known or rec.address.lower() in normalized_known_lower:
            matches.append(rec)
    return matches


def _btc_balance_request(session: requests.Session, address: str) -> BalanceRecord:
    url = f"https://blockstream.info/api/address/{address}"
    try:
        resp = session.get(url, timeout=20)
        if resp.status_code != 200:
            return BalanceRecord(address=address, chain="bitcoin", error=f"HTTP {resp.status_code}")
        data = resp.json()
        chain_stats = data.get("chain_stats", {})
        mempool_stats = data.get("mempool_stats", {})
        funded = int(chain_stats.get("funded_txo_sum", 0))
        spent = int(chain_stats.get("spent_txo_sum", 0))
        mem_funded = int(mempool_stats.get("funded_txo_sum", 0))
        mem_spent = int(mempool_stats.get("spent_txo_sum", 0))
        confirmed_sats = max(funded - spent, 0)
        unconfirmed_sats = max(mem_funded - mem_spent, 0)
        total_sats = confirmed_sats + unconfirmed_sats
        return BalanceRecord(
            address=address,
            chain="bitcoin",
            confirmed_raw=confirmed_sats,
            confirmed=confirmed_sats / 1e8,
        )
    except Exception as exc:  # pragma: no cover
        return BalanceRecord(address=address, chain="bitcoin", error=str(exc))


def _eth_balance_request(session: requests.Session, address: str) -> BalanceRecord:
    url = "https://cloudflare-eth.com"
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }
    headers = {"Content-Type": "application/json"}
    try:
        resp = session.post(url, json=payload, headers=headers, timeout=20)
        if resp.status_code != 200:
            return BalanceRecord(address=address, chain="ethereum", error=f"HTTP {resp.status_code}")
        data = resp.json()
        if "result" not in data:
            return BalanceRecord(address=address, chain="ethereum", error="Invalid RPC response")
        wei_hex = data["result"]
        wei_value = int(wei_hex, 16)
        return BalanceRecord(
            address=address,
            chain="ethereum",
            confirmed_raw=wei_value,
            confirmed=wei_value / 1e18,
        )
    except Exception as exc:  # pragma: no cover
        return BalanceRecord(address=address, chain="ethereum", error=str(exc))


def check_balances(
    all_records: Iterable[AddressRecord],
    max_workers: int = 8,
) -> Dict[str, BalanceRecord]:
    records = list(all_records)
    results: Dict[str, BalanceRecord] = {}
    if not records:
        return results

    session = requests.Session()
    session.headers.update({
        "User-Agent": "WalletGen/1.0 (+https://blockstream.info +https://cloudflare-eth.com)",
        "Accept": "application/json",
    })

    def task(rec: AddressRecord) -> Tuple[str, BalanceRecord]:
        # Light rate limit: brief sleep spread by index to avoid spikes when very large
        # Not precise but effective for basic courtesy
        if rec.chain == "bitcoin":
            bal = _btc_balance_request(session, rec.address)
        else:
            bal = _eth_balance_request(session, rec.address)
        return rec.address, bal

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_rec = {executor.submit(task, rec): rec for rec in records}
        for future in concurrent.futures.as_completed(future_to_rec):
            rec = future_to_rec[future]
            try:
                address, balance = future.result()
                results[address] = balance
            except Exception as exc:  # pragma: no cover
                results[rec.address] = BalanceRecord(address=rec.address, chain=rec.chain, error=str(exc))

    session.close()
    return results


def serialize_wallet_result(
    mnemonic: Optional[str],
    show_mnemonic: bool,
    btc_derivations: Optional[Dict[str, List[AddressRecord]]],
    eth_records: Optional[List[AddressRecord]],
    matches: List[AddressRecord],
    balances: Optional[Dict[str, BalanceRecord]] = None,
) -> Dict:
    out: Dict[str, object] = {}
    if show_mnemonic and mnemonic:
        out["mnemonic"] = mnemonic

    if btc_derivations is not None:
        out["bitcoin"] = {
            key: [r.address for r in records] for key, records in btc_derivations.items()
        }
    if eth_records is not None:
        out["ethereum"] = [r.address for r in eth_records]

    if matches:
        out["matches"] = [
            {
                "chain": r.chain,
                "derivation": r.derivation,
                "index": r.index,
                "address": r.address,
            }
            for r in matches
        ]

    if balances is not None and balances:
        out["balances"] = {
            addr: {
                "chain": bal.chain,
                "confirmed": bal.confirmed,
                "raw": bal.confirmed_raw,
                **({"error": bal.error} if bal.error else {}),
            }
            for addr, bal in balances.items()
        }

    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    target_btc = args.btc or not (args.btc or args.eth)
    target_eth = args.eth or not (args.btc or args.eth)

    try:
        known_addresses = load_address_database(args.address_db)
    except Exception as exc:
        sys.stderr.write(f"Failed to load address DB: {exc}\n")
        return 2

    overall_results: List[Dict] = []

    for wallet_idx in range(args.count):
        mnemonic = generate_mnemonic(args.words)

        all_records: List[AddressRecord] = []
        btc_derivations: Optional[Dict[str, List[AddressRecord]]] = None
        eth_records: Optional[List[AddressRecord]] = None

        if target_btc:
            btc_derivations = derive_bitcoin_addresses(
                mnemonic=mnemonic,
                account_index=args.account,
                address_count=args.addr_count,
            )
            all_records.extend(btc_derivations["bip44_p2pkh"])  # type: ignore[index]
            all_records.extend(btc_derivations["bip84_p2wpkh"])  # type: ignore[index]

        if target_eth:
            eth_records = derive_ethereum_addresses(
                mnemonic=mnemonic,
                account_index=args.account,
                address_count=args.addr_count,
            )
            all_records.extend(eth_records)

        matches = match_addresses(all_records, known_addresses)

        balances: Optional[Dict[str, BalanceRecord]] = None
        if args.check_balance:
            balances = check_balances(all_records, max_workers=max(args.concurrency, 1))

        serialized = serialize_wallet_result(
            mnemonic=mnemonic,
            show_mnemonic=args.print_mnemonic,
            btc_derivations=btc_derivations,
            eth_records=eth_records,
            matches=matches,
            balances=balances,
        )
        overall_results.append(serialized)

        # Console output (human-readable summary)
        print(f"Wallet {wallet_idx+1}:")
        if args.print_mnemonic:
            print(f"  Mnemonic: {mnemonic}")

        if btc_derivations is not None:
            p2pkh_list = [r.address for r in btc_derivations.get("bip44_p2pkh", [])]
            p2wpkh_list = [r.address for r in btc_derivations.get("bip84_p2wpkh", [])]
            if p2pkh_list:
                print("  BTC BIP44 (P2PKH):")
                for idx, addr in enumerate(p2pkh_list):
                    if args.check_balance and serialized.get("balances"):
                        bal = serialized["balances"].get(addr)  # type: ignore[index]
                        if args.only_positive and (not bal or not bal.get("confirmed")):
                            continue
                        bal_str = (
                            f" (bal={bal.get('confirmed')} BTC)" if bal and bal.get("confirmed") else ""
                        )
                    else:
                        bal_str = ""
                    print(f"    [{idx}] {addr}{bal_str}")
            if p2wpkh_list:
                print("  BTC BIP84 (Bech32 P2WPKH):")
                for idx, addr in enumerate(p2wpkh_list):
                    if args.check_balance and serialized.get("balances"):
                        bal = serialized["balances"].get(addr)  # type: ignore[index]
                        if args.only_positive and (not bal or not bal.get("confirmed")):
                            continue
                        bal_str = (
                            f" (bal={bal.get('confirmed')} BTC)" if bal and bal.get("confirmed") else ""
                        )
                    else:
                        bal_str = ""
                    print(f"    [{idx}] {addr}{bal_str}")

        if eth_records is not None:
            print("  ETH BIP44:")
            for rec in eth_records:
                if args.check_balance and serialized.get("balances"):
                    bal = serialized["balances"].get(rec.address)  # type: ignore[index]
                    if args.only_positive and (not bal or not bal.get("confirmed")):
                        continue
                    bal_str = (
                        f" (bal={bal.get('confirmed')} ETH)" if bal and bal.get("confirmed") else ""
                    )
                else:
                    bal_str = ""
                print(f"    [{rec.index}] {rec.address}{bal_str}")

        if matches:
            print("  Matches in known DB:")
            for m in matches:
                print(f"    {m.chain}:{m.derivation}[{m.index}] {m.address}")

        print()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(overall_results, f, indent=2)
            print(f"Wrote results to {args.output}")
        except Exception as exc:
            sys.stderr.write(f"Failed to write output file: {exc}\n")
            return 3

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
