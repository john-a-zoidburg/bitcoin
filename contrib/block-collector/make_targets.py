#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Produce an ordered block-hash allowlist, excluding locally available bodies."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


MAX_BLOCK_BYTES = 4_000_000


def complete_body(path):
    """Check exact transaction serialization and the header's txid Merkle root.

    This guards target selection, not consensus classification. The directories
    must still contain bodies whose proof of work, witness data and historical
    context have been independently checked.
    """
    if not 81 < path.stat().st_size <= MAX_BLOCK_BYTES:
        return None
    data = memoryview(path.read_bytes())
    position = 80

    def take(size):
        nonlocal position
        if size < 0 or size > len(data) - position:
            raise ValueError("Truncated block")
        value = data[position:position + size]
        position += size
        return value

    def compact():
        first = take(1)[0]
        if first < 253:
            return first
        width = {253: 2, 254: 4, 255: 8}[first]
        value = int.from_bytes(take(width), "little")
        if value < {253: 253, 254: 65536, 255: 4294967296}[first] or value > MAX_BLOCK_BYTES:
            raise ValueError("Invalid CompactSize")
        return value

    def vector():
        return take(compact())

    try:
        count = compact()
        if count == 0 or count > (len(data) - position) // 10:
            return None
        txids = []
        coinbase_commitment = False
        coinbase_witness = False
        for index in range(count):
            version = take(4)
            vin_start = position
            inputs = compact()
            witness = inputs == 0
            if witness:
                if take(1)[0] != 1:
                    return None
                vin_start = position
                inputs = compact()
                if inputs == 0:
                    return None
            for _ in range(inputs):
                take(36)
                vector()
                take(4)
            vin_end = position
            vout_start = position
            for _ in range(compact()):
                take(8)
                script = vector()
                if index == 0 and len(script) >= 38 and script[:6] == bytes.fromhex("6a24aa21a9ed"):
                    coinbase_commitment = True
            vout_end = position
            if witness:
                has_witness = False
                for input_index in range(inputs):
                    items = compact()
                    has_witness |= items > 0
                    for _ in range(items):
                        item = vector()
                        if index == 0 and inputs == 1 and input_index == 0 and items == 1 and len(item) == 32:
                            coinbase_witness = True
                if not has_witness:
                    return None
            locktime = take(4)
            digest = hashlib.sha256()
            for part in (version, data[vin_start:vin_end], data[vout_start:vout_end], locktime):
                digest.update(part)
            txids.append(hashlib.sha256(digest.digest()).digest())
        if position != len(data) or (coinbase_commitment and not coinbase_witness):
            return None
        while len(txids) > 1:
            if any(txids[i] == txids[i + 1] for i in range(0, len(txids) - 1, 2)):
                return None
            if len(txids) % 2:
                txids.append(txids[-1])
            txids = [hashlib.sha256(hashlib.sha256(txids[i] + txids[i + 1]).digest()).digest()
                     for i in range(0, len(txids), 2)]
        if txids[0] != data[36:68]:
            return None
        return hashlib.sha256(hashlib.sha256(data[:80]).digest()).digest()[::-1].hex()
    except (ValueError, IndexError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path, help="stale-blocks.csv")
    parser.add_argument("--blocks", action="append", default=[], type=Path, help="Directory of previously validated complete .bin bodies; repeatable")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.output.is_symlink() or output == args.csv.resolve():
        parser.error("Output must be separate from the input CSV and must not be a symlink")
    output_identity = None
    if output.exists():
        metadata = output.stat()
        output_identity = (metadata.st_dev, metadata.st_ino)
        if output.samefile(args.csv):
            parser.error("Output must not overwrite the input CSV")
    have = set()
    rejected = 0
    for directory in args.blocks:
        if not directory.is_dir():
            parser.error(f"Not a block directory: {directory}")
        if output.is_relative_to(directory.resolve()):
            parser.error("Output must be outside the supplied block directories")
        for path in directory.rglob("*.bin"):
            if output_identity is not None:
                metadata = path.stat()
                if (metadata.st_dev, metadata.st_ino) == output_identity:
                    parser.error("Output must not overwrite a supplied block file")
            block_hash = complete_body(path)
            if block_hash is None:
                rejected += 1
            else:
                have.add(block_hash)
    selected = []
    seen = set()
    with args.csv.open(newline="", encoding="utf-8") as source:
        for number, row in enumerate(csv.reader(source), 1):
            if not row or row[0].lower() == "height":
                continue
            if len(row) < 2:
                parser.error(f"Missing block hash on CSV line {number}")
            block_hash = row[1].strip().lower()
            try:
                valid = len(block_hash) == 64 and len(bytes.fromhex(block_hash)) == 32 and int(block_hash, 16) != 0
            except ValueError:
                valid = False
            if not valid:
                parser.error(f"Invalid block hash on CSV line {number}")
            if block_hash not in have and block_hash not in seen:
                selected.append(block_hash)
                seen.add(block_hash)
    if not selected:
        parser.error("No missing block bodies selected")
    if len(selected) > 100000:
        parser.error("Too many missing block bodies (maximum 100000)")
    temporary = None
    previous_mask = os.umask(0o077)
    os.umask(previous_mask)
    mode = stat.S_IMODE(output.stat().st_mode) if output.exists() else 0o666 & ~previous_mask
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=output.parent, prefix=f".{output.name}.", delete=False) as destination:
            temporary = Path(destination.name)
            destination.write("\n".join(selected) + "\n")
            destination.flush()
            if hasattr(os, "fchmod"):
                os.fchmod(destination.fileno(), mode)
            else:
                os.chmod(temporary, mode)
            os.fsync(destination.fileno())
        os.replace(temporary, output)
        if os.name != "nt":
            descriptor = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(json.dumps({"targets": len(selected), "existing_body_hashes": len(have), "incomplete_or_inconsistent_bodies": rejected}), file=sys.stderr)


if __name__ == "__main__":
    main()
