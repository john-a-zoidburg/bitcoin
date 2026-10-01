#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Archive allowlisted raw blocks over inbound connections without chainstate submission."""

import hashlib
import json
from pathlib import Path

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import CInv, MSG_BLOCK, MSG_WITNESS_FLAG, NODE_WITNESS, msg_block, msg_generic, msg_headers, msg_notfound
from test_framework.p2p import P2PInterface, P2P_SERVICES, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class ArchivePeer(P2PInterface):
    def __init__(self, responses):
        super().__init__()
        self.responses = responses
        self.queries = []

    def peer_connect_send_version(self, services):
        super().peer_connect_send_version(services)
        self.on_connection_send_msg.strSubVer = "/btcwire:0.5.0/btcd:0.26.2/"

    def on_getdata(self, message):
        for inv in message.inv:
            self.queries.append(inv)
            response = self.responses.get(inv.hash)
            if response is None:
                notfound = msg_notfound()
                notfound.vec = [CInv(inv.type, inv.hash)]
                self.send_without_ping(notfound)
            elif response == "timeout":
                pass
            elif isinstance(response, bytes):
                self.send_without_ping(msg_generic(b"block", response))
            else:
                self.send_without_ping(msg_block(response))


class BlockCollectorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], []]

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getblockcollectorinfo()["enabled"], False)
        genesis = int(node.getbestblockhash(), 16)
        block = create_block(genesis, create_coinbase(1), ntime=node.getblockheader(node.getbestblockhash())["time"] + 1)
        block.solve()
        raw = block.serialize()
        malformed = create_block(genesis, create_coinbase(1), ntime=block.nTime + 1)
        malformed.solve()
        # Its real header survives, followed by deliberately invalid serialization.
        malformed_raw = malformed.serialize()[:80] + b"\xff"
        absent, unanswered = 0x1234, 0x5678
        self.targets = Path(self.options.tmpdir) / "collector-targets.txt"
        self.targets.write_text("\n".join(f"{target:064x}" for target in (block.hash_int, absent, unanswered, malformed.hash_int)) + "\n")
        archive = Path(self.options.tmpdir) / "block-archive"
        self.restart_node(0, extra_args=[
            f"-blockcollector={self.targets}", f"-blockcollectordir={archive}", "-blockcollectorrandomize=0",
            "-blockcollectorinterval=50", "-blockcollectorglobalinterval=20", "-blockcollectortimeout=300",
        ])
        # A second daemon must not silently share the same archive/log.
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(
            extra_args=[f"-blockcollector={self.targets}", f"-blockcollectordir={archive}"],
            expected_msg="Error: Cannot initialize peer manager: Block collector archive is already in use",
        )
        node.add_p2p_connection(P2PInterface())
        assert_equal(node.getblockcollectorinfo()["peers"], 0)
        responses = {block.hash_int: block, unanswered: "timeout", malformed.hash_int: malformed_raw}
        peer = node.add_p2p_connection(ArchivePeer(responses), wait_for_verack=False)
        peer.wait_for_verack()
        peer.sync_with_ping()
        assert_equal(peer.last_message["version"].relay, 0)
        self.wait_until(lambda: node.getblockcollectorinfo()["responses"] == 2 and node.getblockcollectorinfo()["queue_items"] == 0)
        stats = node.getblockcollectorinfo()
        assert_equal(stats["targets"], 4)
        assert_equal(stats["requests"], 4)
        assert_equal(stats["notfound"], 1)
        assert_equal(stats["timeouts"], 1)
        assert_equal(stats["pending"], 0)
        assert_equal(stats["files"], 2)
        assert_equal(stats["paused"], "")
        assert_equal(node.getblockcount(), 0)
        assert_equal(node.getrawmempool(), [])
        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, block.hash_hex)
        assert peer.is_connected
        with p2p_lock:
            assert_equal([inv.hash for inv in peer.queries], [block.hash_int, absent, unanswered, malformed.hash_int])
            assert_equal([inv.type for inv in peer.queries], [MSG_BLOCK | MSG_WITNESS_FLAG] * 4)
        for target, payload in ((block.hash_int, raw), (malformed.hash_int, malformed_raw)):
            filename = f"{target:064x}-{hashlib.sha256(payload).hexdigest()}.bin"
            assert_equal((archive / filename).read_bytes(), payload)
        # A second connection is queried independently, and duplicate bytes do
        # not create extra files. Negative replies remain ordinary survey results.
        other = node.add_p2p_connection(ArchivePeer(responses), wait_for_verack=False)
        other.wait_for_verack()
        other.sync_with_ping()
        self.wait_until(lambda: node.getblockcollectorinfo()["duplicates"] == 2 and node.getblockcollectorinfo()["queue_items"] == 0)
        assert_equal(node.getblockcollectorinfo()["files"], 2)
        assert_equal(node.getblockcount(), 0)
        assert other.is_connected
        legacy = node.add_p2p_connection(ArchivePeer(responses), wait_for_verack=False, services=P2P_SERVICES & ~NODE_WITNESS)
        legacy.wait_for_verack()
        legacy.sync_with_ping()
        self.wait_until(lambda: node.getblockcollectorinfo()["duplicates"] == 4 and node.getblockcollectorinfo()["queue_items"] == 0)
        with p2p_lock:
            assert_equal([inv.type for inv in legacy.queries], [MSG_BLOCK] * 4)
        self.wait_until(lambda: node.getblockcollectorinfo()["queue_items"] == 0)
        events = [json.loads(line) for line in (archive / "events.jsonl").read_text().splitlines()]
        assert_equal(sum(event["event"] == "block_response" for event in events), 6)
        node.disconnect_p2ps()
        self.wait_until(lambda: node.getblockcollectorinfo()["peers"] == 0)
        self.wait_until(lambda: node.getblockcollectorinfo()["queue_items"] == 0)
        events = [json.loads(line) for line in (archive / "events.jsonl").read_text().splitlines()]
        summaries = [event for event in events if event["event"] == "peer_disconnected"]
        assert_equal(len(summaries), 3)
        assert_equal(sum(event["notfound"] for event in summaries), 3)
        assert_equal(sum(event["timeouts"] for event in summaries), 3)
        # Previously saved files count towards the budget after a restart.
        self.restart_node(0, extra_args=[
            f"-blockcollector={self.targets}", f"-blockcollectordir={archive}", "-blockcollectorrandomize=0", "-blockcollectormaxfiles=1",
        ])
        limited = node.add_p2p_connection(ArchivePeer(responses), wait_for_verack=False)
        limited.wait_for_verack()
        limited.sync_with_ping()
        self.wait_until(lambda: node.getblockcollectorinfo()["paused"] == "archive limit reached")
        self.wait_until(lambda: "Block collector paused: archive limit reached" in (node.chain_path / "debug.log").read_text())
        assert_equal(node.getblockcollectorinfo()["requests"], 0)
        assert_equal(node.getblockcollectorinfo()["files"], 2)

        # The collector must not swallow a response also requested through Core's
        # normal download machinery. Hold its first request, then fetch normally.
        self.targets.write_text(block.hash_hex + "\n")
        self.restart_node(0, extra_args=[
            f"-blockcollector={self.targets}", f"-blockcollectordir={archive}", "-blockcollectorrandomize=0",
            "-blockcollectortimeout=60000",
        ])
        overlap = node.add_p2p_connection(ArchivePeer({block.hash_int: "timeout"}), wait_for_verack=False)
        overlap.wait_for_verack()
        overlap.sync_with_ping()
        self.wait_until(lambda: node.getblockcollectorinfo()["requests"] == 1)
        node.submitheader(raw[:80].hex())
        node.getblockfrompeer(block.hash_hex, node.getpeerinfo()[0]["id"])
        overlap.wait_until(lambda: len(overlap.queries) >= 2)
        overlap.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash_hex)
        self.wait_until(lambda: node.getblockcollectorinfo()["queue_items"] == 0)
        assert_equal(node.getblockcollectorinfo()["responses"], 1)
        assert_equal(node.getblockcollectorinfo()["duplicates"], 1)
        # Subsequent ordinary synchronization still works while the collector is
        # enabled, including hashes outside its allowlist.
        following = create_block(block.hash_int, create_coinbase(2), ntime=block.nTime + 1)
        following.solve()
        with p2p_lock:
            overlap.responses[following.hash_int] = following
        overlap.send_and_ping(msg_headers([following]))
        self.wait_until(lambda: node.getbestblockhash() == following.hash_hex)
        assert_equal(node.getblockcollectorinfo()["responses"], 1)

        # Using the network data directory as the archive must preserve Core's
        # independent data-directory lock, including after archival setup.
        self.restart_node(0, extra_args=[f"-blockcollector={self.targets}", f"-blockcollectordir={node.chain_path}"])
        assert (node.chain_path / ".blockcollector.lock").is_file()
        self.nodes[1].assert_start_raises_init_error(
            extra_args=[f"-datadir={node.datadir_path}"],
            expected_msg="Cannot obtain a lock on directory",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.stop_node(0)
        for argument, message in (
            ("-noblockcollectoragent", "Negating of -blockcollectoragent"),
            ("-noblockcollectordir", "Negating of -blockcollectordir"),
            ("-noblockcollectorinterval", "Negating of -blockcollectorinterval"),
            ("-blockcollectoragent=", "-blockcollectoragent must not be empty"),
            ("-blockcollectordir=", "-blockcollectordir must not be empty"),
            ("-blockcollectormaxpending=0", "-blockcollectormaxpending is outside its permitted range"),
            ("-blockcollectortimeout=30s", "-blockcollectortimeout must be a whole number without units"),
            ("-blockcollectorinterval=2.5", "-blockcollectorinterval must be a whole number without units"),
            ("-blockcollectormaxfiles=100garbage", "-blockcollectormaxfiles must be a whole number without units"),
            ("-blockcollectorpeerbytes=0garbage", "-blockcollectorpeerbytes must be a whole number without units"),
            ("-blockcollectortimeout=99999999999999999999", "-blockcollectortimeout must be a whole number without units"),
        ):
            node.assert_start_raises_init_error(
                extra_args=[f"-blockcollector={self.targets}", argument],
                expected_msg=message, match=ErrorMatch.PARTIAL_REGEX,
            )
        self.start_node(0, extra_args=["-noblockcollector"])
        assert_equal(node.getblockcollectorinfo()["enabled"], False)


if __name__ == "__main__":
    BlockCollectorTest(__file__).main()
