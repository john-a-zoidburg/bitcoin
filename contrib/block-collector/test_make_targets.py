#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise target selection and protection of the recovery inputs."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import struct
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("make_targets.py")


class MakeTargetsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.csv = self.root / "stale-blocks.csv"
        self.blocks = self.root / "validated-blocks"
        self.blocks.mkdir()
        self.output = self.root / "targets.txt"
        self.transaction = (struct.pack("<I", 1) + b"\x01" + bytes(32) + b"\xff" * 4 + b"\x02\x01\x01" + b"\xff" * 4
                            + b"\x01" + struct.pack("<Q", 5_000_000_000) + b"\x01\x51" + bytes(4))
        merkle = hashlib.sha256(hashlib.sha256(self.transaction).digest()).digest()
        self.header = bytes(range(36)) + merkle + bytes(range(68, 80))
        self.complete = self.header + b"\x01" + self.transaction
        self.block_hash = hashlib.sha256(hashlib.sha256(self.header).digest()).digest()[::-1].hex()
        self.other_hash = "11" * 32
        self.csv.write_text(f"height,hash\n1,{self.block_hash}\n2,{self.other_hash}\n1,{self.block_hash.upper()}\n", encoding="ascii")

    def run_script(self, output=None):
        return subprocess.run([
            sys.executable, "-B", str(SCRIPT), "--csv", str(self.csv),
            "--blocks", str(self.blocks), "--output", str(output or self.output),
        ], text=True, capture_output=True, check=False)

    def test_header_only_is_not_excluded(self):
        (self.blocks / "header.bin").write_bytes(self.header)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().splitlines(), [self.block_hash, self.other_hash])
        self.assertEqual(json.loads(result.stderr)["existing_body_hashes"], 0)

    def test_validated_body_is_excluded_and_existing_list_replaced(self):
        (self.blocks / "complete.bin").write_bytes(self.complete)
        self.output.write_text("previous contents\n", encoding="ascii")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), self.other_hash + "\n")
        self.assertEqual(json.loads(result.stderr)["existing_body_hashes"], 1)
        self.assertEqual(list(self.root.glob(".targets.txt.*")), [])

    def test_invalid_csv_leaves_previous_list_intact(self):
        self.csv.write_text("1,not-a-hash\n", encoding="ascii")
        self.output.write_text("previous contents\n", encoding="ascii")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(), "previous contents\n")

    def test_inputs_cannot_be_overwritten(self):
        original = self.csv.read_bytes()
        self.assertNotEqual(self.run_script(self.csv).returncode, 0)
        self.assertEqual(self.csv.read_bytes(), original)
        body = self.blocks / "complete.bin"
        payload = self.complete
        body.write_bytes(payload)
        self.assertNotEqual(self.run_script(body).returncode, 0)
        self.assertEqual(body.read_bytes(), payload)
        link = self.root / "body-link.txt"
        os.link(body, link)
        self.assertNotEqual(self.run_script(link).returncode, 0)
        self.assertEqual(body.read_bytes(), payload)

    def test_truncated_inconsistent_and_trailing_bytes_remain_targets(self):
        for payload in (self.header + b"\x01", self.complete[:-1], self.complete + b"\x00",
                        self.complete[:-5] + b"\x52" + self.complete[-4:]):
            with self.subTest(length=len(payload)):
                (self.blocks / "capture.bin").write_bytes(payload)
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.output.read_text().splitlines(), [self.block_hash, self.other_hash])
                self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 1)

    def test_witness_and_stripped_serializations_share_the_header_hash(self):
        witness_transaction = (self.transaction[:4] + b"\x00\x01" + self.transaction[4:-4]
                               + b"\x01\x20" + bytes(32) + self.transaction[-4:])
        (self.blocks / "witness.bin").write_bytes(self.header + b"\x01" + witness_transaction)
        (self.blocks / "stripped.bin").write_bytes(self.complete)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), self.other_hash + "\n")
        self.assertEqual(json.loads(result.stderr)["existing_body_hashes"], 1)
        self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 0)

    def test_noncanonical_compactsize_remains_a_target(self):
        (self.blocks / "capture.bin").write_bytes(self.header + b"\xfd\x01\x00" + self.transaction)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().splitlines(), [self.block_hash, self.other_hash])
        self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 1)

    def test_duplicate_transaction_merkle_mutation_remains_a_target(self):
        transactions = [self.transaction, self.transaction[:-4] + struct.pack("<I", 1),
                        self.transaction[:-4] + struct.pack("<I", 2)]
        hashes = [hashlib.sha256(hashlib.sha256(tx).digest()).digest() for tx in transactions]
        level = hashes + [hashes[-1]]
        level = [hashlib.sha256(hashlib.sha256(level[i] + level[i + 1]).digest()).digest() for i in (0, 2)]
        root = hashlib.sha256(hashlib.sha256(level[0] + level[1]).digest()).digest()
        header = self.header[:36] + root + self.header[68:]
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        self.csv.write_text(f"1,{block_hash}\n2,{self.other_hash}\n", encoding="ascii")
        (self.blocks / "mutated.bin").write_bytes(header + b"\x04" + b"".join(transactions + [transactions[-1]]))
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().splitlines(), [block_hash, self.other_hash])
        self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 1)

    def test_commitment_requires_coinbase_witness_data(self):
        commitment = hashlib.sha256(hashlib.sha256(bytes(64)).digest()).digest()
        script = bytes.fromhex("6a24aa21a9ed") + commitment
        transaction = self.transaction[:-6] + bytes([len(script)]) + script + bytes(4)
        merkle = hashlib.sha256(hashlib.sha256(transaction).digest()).digest()
        header = self.header[:36] + merkle + self.header[68:]
        block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
        self.csv.write_text(f"1,{block_hash}\n2,{self.other_hash}\n", encoding="ascii")
        (self.blocks / "stripped.bin").write_bytes(header + b"\x01" + transaction)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().splitlines(), [block_hash, self.other_hash])
        self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 1)
        witness = transaction[:4] + b"\x00\x01" + transaction[4:-4] + b"\x01\x20" + bytes(32) + transaction[-4:]
        (self.blocks / "witness.bin").write_bytes(header + b"\x01" + witness)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), self.other_hash + "\n")
        self.assertEqual(json.loads(result.stderr)["incomplete_or_inconsistent_bodies"], 1)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_output_respects_umask_and_preserves_existing_mode(self):
        original = os.umask(0o022)
        try:
            self.assertEqual(self.run_script().returncode, 0)
        finally:
            os.umask(original)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
        self.output.chmod(0o640)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
