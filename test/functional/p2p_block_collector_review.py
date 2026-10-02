#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Collector archival properties over real P2P transports.

- Witness and stripped serializations are archived byte-for-byte and kept apart.
- A body arriving after the collector timeout is archived outside chainstate.
- Repeated and header-consistent but body-inconsistent replies to a
  collector-only request stay within the per-connection bound and do not
  reach Core's normal block path, so they do not penalize the peer.
"""

import copy
import hashlib
from pathlib import Path

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import (
    CInv,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    NODE_WITNESS,
    msg_block,
    msg_generic,
    msg_no_witness_block,
    msg_notfound,
)
from test_framework.p2p import P2PInterface, P2P_SERVICES, p2p_lock
from test_framework.script import CScript, OP_0
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class CollectorPeer(P2PInterface):
    """Claims a btcd user agent; answers getdata from a table or withholds."""

    def __init__(self, blocks, withhold=()):
        super().__init__()
        self.blocks = blocks
        self.withhold = set(withhold)
        self.queries = []

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.strSubVer = "/btcwire:0.5.0/btcd:0.24.2/"

    def on_getdata(self, message):
        for inv in message.inv:
            self.queries.append(inv)
            if inv.hash in self.withhold:
                continue
            block = self.blocks.get(inv.hash)
            if block is None:
                reply = msg_notfound()
                reply.vec = [CInv(inv.type, inv.hash)]
                self.send_without_ping(reply)
            elif inv.type & MSG_WITNESS_FLAG:
                self.send_without_ping(msg_block(block))
            else:
                self.send_without_ping(msg_no_witness_block(block))


class BlockCollectorReviewTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def start_collector(self, name, targets, extra=()):
        tmpdir = Path(self.options.tmpdir)
        target_file = tmpdir / f"{name}-targets.txt"
        target_file.write_text("".join(f"{target:064x}\n" for target in targets))
        archive = tmpdir / f"{name}-archive"
        self.restart_node(0, extra_args=[
            f"-blockcollector={target_file}", f"-blockcollectordir={archive}", "-blockcollectorrandomize=0",
            "-blockcollectorinterval=50", "-blockcollectorglobalinterval=10", *extra,
        ])
        return archive

    def connect(self, peer, services=P2P_SERVICES):
        connection = self.nodes[0].add_p2p_connection(peer, wait_for_verack=False, services=services)
        connection.wait_for_verack()
        connection.sync_with_ping()
        return connection

    @staticmethod
    def archived(archive, block, payload):
        path = archive / f"{block.hash_hex}-{hashlib.sha256(payload).hexdigest()}.bin"
        return path.is_file() and path.read_bytes() == payload

    def assert_outside_chainstate(self, block):
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 0)
        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, block.hash_hex)

    def run_test(self):
        tip = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())
        self.genesis = int(tip["hash"], 16)
        self.ntime = tip["time"] + 1
        self.test_witness_payloads()
        self.test_late_reply()
        self.test_repeated_and_inconsistent_replies()
        self.test_legacy_reply_during_normal_witness_download()

    def test_legacy_reply_during_normal_witness_download(self):
        self.log.info("A stripped collector reply must not penalize its peer during another peer's normal witness download")
        node = self.nodes[0]
        block = create_block(self.genesis, create_coinbase(1), ntime=self.ntime + 3)
        add_witness_commitment(block)
        block.solve()
        archive = self.start_collector("overlap", [block.hash_int], extra=["-blockcollectortimeout=60000"])
        legacy = self.connect(CollectorPeer({block.hash_int: block}, withhold=[block.hash_int]), services=P2P_SERVICES & ~NODE_WITNESS)
        self.wait_until(lambda: node.getblockcollectorinfo()["pending"] == 1)
        before = {peer["id"] for peer in node.getpeerinfo()}
        normal = node.add_p2p_connection(P2PInterface())
        normal_id = next(peer["id"] for peer in node.getpeerinfo() if peer["id"] not in before)
        node.submitheader(block.serialize()[:80].hex())
        node.getblockfrompeer(block.hash_hex, normal_id)
        normal.wait_for_getdata([block.hash_int])
        legacy.send_and_ping(msg_no_witness_block(block))
        self.wait_until(lambda: node.getblockcollectorinfo()["responses"] == 1 and node.getblockcollectorinfo()["queue_items"] == 0)
        assert legacy.is_connected
        assert_equal(node.getblockcount(), 0)
        assert self.archived(archive, block, block.serialize(with_witness=False))
        normal.send_and_ping(msg_block(block))
        self.wait_until(lambda: node.getbestblockhash() == block.hash_hex)
        assert legacy.is_connected
        assert_equal(node.getblockcollectorinfo()["responses"], 1)
        node.disconnect_p2ps()

    def test_witness_payloads(self):
        self.log.info("Witness and stripped serializations are archived exactly and separately")
        node = self.nodes[0]
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(0x1234, 0))]
        tx.vout = [CTxOut(1000, CScript([OP_0, bytes(20)]))]
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x30" * 72, b"\x02" * 33]
        block = create_block(self.genesis, create_coinbase(1), ntime=self.ntime, txlist=[tx])
        add_witness_commitment(block)
        block.solve()
        with_witness, stripped = block.serialize(with_witness=True), block.serialize(with_witness=False)
        assert len(with_witness) > len(stripped)
        archive = self.start_collector("witness", [block.hash_int])
        witness_peer = self.connect(CollectorPeer({block.hash_int: block}))
        legacy_peer = self.connect(CollectorPeer({block.hash_int: block}), services=P2P_SERVICES & ~NODE_WITNESS)
        self.wait_until(lambda: node.getblockcollectorinfo()["responses"] == 2 and node.getblockcollectorinfo()["queue_items"] == 0)
        with p2p_lock:
            assert_equal([inv.type for inv in witness_peer.queries], [MSG_BLOCK | MSG_WITNESS_FLAG])
            assert_equal([inv.type for inv in legacy_peer.queries], [MSG_BLOCK])
        assert self.archived(archive, block, with_witness)
        assert self.archived(archive, block, stripped)
        assert_equal(node.getblockcollectorinfo()["files"], 2)
        self.assert_outside_chainstate(block)
        node.disconnect_p2ps()

    def test_late_reply(self):
        self.log.info("A body arriving after the collector timeout is still archived")
        node = self.nodes[0]
        block = create_block(self.genesis, create_coinbase(1), ntime=self.ntime + 1)
        block.solve()
        archive = self.start_collector("late", [block.hash_int], extra=["-blockcollectortimeout=200"])
        peer = self.connect(CollectorPeer({block.hash_int: block}, withhold=[block.hash_int]))
        self.wait_until(lambda: node.getblockcollectorinfo()["timeouts"] == 1)
        peer.send_and_ping(msg_block(block))
        self.wait_until(lambda: node.getblockcollectorinfo()["queue_items"] == 0)
        stats = node.getblockcollectorinfo()
        assert_equal((stats["responses"], stats["files"], stats["pending"]), (1, 1, 0))
        assert self.archived(archive, block, block.serialize())
        self.assert_outside_chainstate(block)
        assert peer.is_connected
        node.disconnect_p2ps()

    def test_repeated_and_inconsistent_replies(self):
        self.log.info("Repeated and body-inconsistent replies are bounded and not penalized")
        node = self.nodes[0]
        block = create_block(self.genesis, create_coinbase(1), ntime=self.ntime + 2)
        block.solve()
        archive = self.start_collector("repeat", [block.hash_int])
        peer = self.connect(CollectorPeer({block.hash_int: block}))
        self.wait_until(lambda: node.getblockcollectorinfo()["responses"] == 1)
        for _ in range(20):
            peer.send_without_ping(msg_block(block))
        # Keep the authentic header but change the body, so the Merkle root no
        # longer matches. On Core's normal path this is a mutated block.
        for change in range(1, 7):
            variant = copy.deepcopy(block)
            variant.vtx[0].vout[0].nValue -= change
            peer.send_without_ping(msg_generic(b"block", variant.serialize()))
        peer.sync_with_ping()
        self.wait_until(lambda: node.getblockcollectorinfo()["queue_items"] == 0)
        stats = node.getblockcollectorinfo()
        assert_equal((stats["responses"], stats["files"]), (4, 4))
        assert_equal(len([path for path in archive.iterdir() if path.suffix == ".bin"]), 4)
        assert self.archived(archive, block, block.serialize())
        self.assert_outside_chainstate(block)
        assert peer.is_connected
        assert_equal(len(node.getpeerinfo()), 1)
        # Control: the same body from a connection the collector never queried
        # takes Core's normal path, which rejects it as mutated.
        plain = node.add_p2p_connection(P2PInterface())
        variant = copy.deepcopy(block)
        variant.vtx[0].vout[0].nValue -= 1
        plain.send_without_ping(msg_generic(b"block", variant.serialize()))
        plain.wait_for_disconnect()
        self.assert_outside_chainstate(block)
        assert peer.is_connected
        node.disconnect_p2ps()


if __name__ == "__main__":
    BlockCollectorReviewTest(__file__).main()
