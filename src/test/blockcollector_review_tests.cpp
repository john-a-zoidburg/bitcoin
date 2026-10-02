// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Regression coverage for archival data preservation and peer resource limits.

#include <addrman.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <net.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/blockcollector.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <vector>

#ifndef WIN32
#include <csignal>
#include <sys/resource.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

namespace {
uint256 HeaderHash(std::span<const unsigned char> bytes) { return Hash(bytes.first(80)); }

//! 80-byte pseudo-header derived from seed, followed by body bytes.
std::vector<unsigned char> Payload(uint8_t seed, size_t size, uint8_t fill = 0)
{
    std::vector<unsigned char> bytes(size, fill);
    for (size_t i{0}; i < 80; ++i) bytes[i] = uint8_t(seed + i);
    return bytes;
}

std::vector<uint256> Targets(size_t count)
{
    std::vector<uint256> targets;
    for (size_t i{1}; i <= count; ++i) targets.push_back(ArithToUint256(arith_uint256{i}));
    return targets;
}

node::BlockCollector::Options MakeOptions(const fs::path& root, const std::vector<uint256>& targets)
{
    fs::create_directories(root);
    node::BlockCollector::Options options;
    options.randomize = false;
    options.targets = root / "targets.txt";
    options.directory = root / "archive";
    std::ofstream file{options.targets.std_path()};
    for (const auto& target : targets) file << target.ToString() << '\n';
    return options;
}

std::string ReadText(const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    return {std::istreambuf_iterator<char>{file}, {}};
}

std::vector<unsigned char> ReadBytes(const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    return {std::istreambuf_iterator<char>{file}, {}};
}

uint64_t ArchiveBytes(const fs::path& directory)
{
    uint64_t total{0};
    for (const auto& entry : fs::directory_iterator{directory}) {
        if (entry.path().extension() == ".bin" || entry.path().extension() == ".tmp") total += entry.file_size();
    }
    return total;
}

int64_t Millis(SteadyClock::time_point time)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
}

const auto START{SteadyClock::time_point{} + 1h};
} // namespace

BOOST_FIXTURE_TEST_SUITE(blockcollector_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(late_replies_after_timeout_keep_data_and_current_request)
{
    const auto a{Payload(1, 200)}, b{Payload(2, 200)};
    auto options{MakeOptions(m_path_root / "late", {HeaderHash(a), HeaderHash(b)})};
    node::BlockCollector collector{options};
    BOOST_REQUIRE(collector.AddPeer(1, "127.0.0.1:1", "/btcd:0.24.2/", true, true));
    BOOST_REQUIRE(collector.NextRequest(1, START));
    // The request for a times out; the same scheduling pass asks for b.
    const auto next{collector.NextRequest(1, START + options.timeout)};
    BOOST_REQUIRE(next);
    BOOST_CHECK(next->hash == HeaderHash(b));
    BOOST_CHECK_EQUAL(collector.GetStats().timeouts, 1U);
    // A late notfound and a late body for a are both recorded and preserved,
    // and neither clears the request for b or its eviction preference.
    collector.NotFound(1, {CInv{MSG_WITNESS_BLOCK, HeaderHash(a)}});
    BOOST_CHECK(collector.ReceiveBlock(1, a) == HeaderHash(a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 1U);
    BOOST_CHECK_EQUAL(collector.GetStats().files, 1U);
    BOOST_CHECK_EQUAL(collector.ProtectionDeadline(1), Millis(START + options.timeout + options.timeout));
    BOOST_CHECK(collector.ReceiveBlock(1, b) == HeaderHash(b));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 0U);
    BOOST_CHECK_EQUAL(collector.ProtectionDeadline(1), 0);
    BOOST_CHECK_EQUAL(collector.GetStats().files, 2U);
}

BOOST_AUTO_TEST_CASE(witness_and_stripped_serializations_are_preserved_exactly)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 50 * COIN;
    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    spend.vin[0].scriptWitness.stack = {std::vector<unsigned char>(72, 0x30), std::vector<unsigned char>(33, 0x02)};
    spend.vout.resize(1);
    spend.vout[0].nValue = 1;
    spend.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0x11);
    CBlock block;
    block.nVersion = 0x20000000;
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    block.vtx = {MakeTransactionRef(coinbase), MakeTransactionRef(spend)};
    block.hashMerkleRoot = BlockMerkleRoot(block);
    DataStream with_witness, without_witness;
    with_witness << TX_WITH_WITNESS(block);
    without_witness << TX_NO_WITNESS(block);
    BOOST_REQUIRE_GT(with_witness.size(), without_witness.size());

    auto options{MakeOptions(m_path_root / "witness", {block.GetHash()})};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "127.0.0.1:1", "/btcd:0.24.2/", true, /*witness=*/true);
    collector.AddPeer(2, "127.0.0.1:2", "/btcd:0.20.0/", true, /*witness=*/false);
    const auto witness_request{collector.NextRequest(1, START)};
    const auto legacy_request{collector.NextRequest(2, START + 1s)};
    BOOST_REQUIRE(witness_request && legacy_request);
    BOOST_CHECK_EQUAL(witness_request->type, MSG_WITNESS_BLOCK);
    BOOST_CHECK_EQUAL(legacy_request->type, MSG_BLOCK);
    BOOST_CHECK(collector.ReceiveBlock(1, MakeUCharSpan(with_witness)) == block.GetHash());
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK(collector.ReceiveBlock(2, MakeUCharSpan(without_witness)) == block.GetHash());
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    // Both serializations survive byte-for-byte under the same header hash.
    size_t files{0};
    for (const auto& entry : fs::directory_iterator{options.directory}) {
        if (entry.path().extension() != ".bin") continue;
        ++files;
        BOOST_CHECK(fs::PathToString(entry.path().filename()).starts_with(block.GetHash().ToString() + "-"));
        const auto stored{ReadBytes(entry.path())};
        const auto& expected{stored.size() == with_witness.size() ? with_witness : without_witness};
        BOOST_CHECK(std::ranges::equal(stored, MakeUCharSpan(expected)));
        CBlock decoded;
        DataStream{std::span<const uint8_t>{stored}} >> TX_WITH_WITNESS(decoded);
        BOOST_CHECK(decoded.GetHash() == block.GetHash());
        BOOST_CHECK_EQUAL(decoded.vtx[1]->HasWitness(), stored.size() == with_witness.size());
    }
    BOOST_CHECK_EQUAL(files, 2U);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(unwritable_archive_pauses_without_phantom_accounting)
{
    if (geteuid() == 0) return; // Permissions do not constrain root.
    const auto a{Payload(3, 300)}, b{Payload(4, 300)};
    auto options{MakeOptions(m_path_root / "readonly", {HeaderHash(a), HeaderHash(b)})};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "127.0.0.1:1", "/btcd:0.24.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, START));
    fs::permissions(options.directory, fs::perms::owner_read | fs::perms::owner_exec, fs::perm_options::replace);
    const auto captured{collector.ReceiveBlock(1, a)};
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    fs::permissions(options.directory, fs::perms::owner_all, fs::perm_options::replace);
    // The response is still claimed (never reaches chainstate) but nothing is counted.
    BOOST_CHECK(captured == HeaderHash(a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    const auto stats{collector.GetStats()};
    BOOST_CHECK_EQUAL(stats.paused, "cannot preserve block response");
    BOOST_CHECK_EQUAL(stats.files, 0U);
    BOOST_CHECK_EQUAL(stats.bytes, 0U);
    BOOST_CHECK_EQUAL(stats.dropped_responses, 1U);
    BOOST_CHECK_EQUAL(ArchiveBytes(options.directory), 0U);
    const auto log{ReadText(options.directory / "events.jsonl")};
    BOOST_CHECK(log.find("\"saved\":false") != std::string::npos);
    BOOST_CHECK(log.find("cannot preserve block response") != std::string::npos);
    // Requests stay paused for the rest of the run even after storage recovers.
    BOOST_CHECK(!collector.NextRequest(1, START + 1min));
}

BOOST_AUTO_TEST_CASE(interrupted_write_is_retained_and_budgeted)
{
    // Simulate running out of space part-way through a raw write.
    const auto a{Payload(5, 1'000'000)};
    auto options{MakeOptions(m_path_root / "efbig", {HeaderHash(a)})};
    std::optional<node::BlockCollector> running{std::in_place, options};
    auto& collector{*running};
    collector.AddPeer(1, "127.0.0.1:1", "/btcd:0.24.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, START));
    rlimit original;
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_FSIZE, &original), 0);
    const auto previous_handler{std::signal(SIGXFSZ, SIG_IGN)};
    rlimit limited{original};
    limited.rlim_cur = 64 * 1024;
    BOOST_REQUIRE_EQUAL(setrlimit(RLIMIT_FSIZE, &limited), 0);
    const auto captured{collector.ReceiveBlock(1, a)};
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    setrlimit(RLIMIT_FSIZE, &original);
    std::signal(SIGXFSZ, previous_handler);
    BOOST_CHECK(captured == HeaderHash(a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    const auto stats{collector.GetStats()};
    BOOST_CHECK_EQUAL(stats.paused, "cannot preserve block response");
    // Whatever reached disk is retained, counted and named in the event log.
    const auto on_disk{ArchiveBytes(options.directory)};
    BOOST_CHECK_GT(on_disk, 0U);
    BOOST_CHECK_LT(on_disk, a.size());
    BOOST_CHECK_EQUAL(stats.bytes, on_disk);
    BOOST_CHECK_EQUAL(stats.files, 1U);
    BOOST_CHECK(ReadText(options.directory / "events.jsonl").find("\"partial_file\"") != std::string::npos);
    // A restart keeps counting it and refuses to resume until it is inspected.
    running.reset();
    node::BlockCollector restarted{options};
    BOOST_CHECK_EQUAL(restarted.GetStats().bytes, on_disk);
    BOOST_CHECK_EQUAL(restarted.GetStats().paused, "incomplete archive files require inspection");
}
#endif

BOOST_AUTO_TEST_CASE(storage_budget_holds_against_reconnecting_variant_flood)
{
    std::vector<std::vector<unsigned char>> blocks;
    std::vector<uint256> targets;
    for (uint8_t i{0}; i < 6; ++i) {
        blocks.push_back(Payload(40 + i, 700'000));
        targets.push_back(HeaderHash(blocks.back()));
    }
    auto options{MakeOptions(m_path_root / "flood", targets)};
    options.max_bytes = 8 * 1024 * 1024;
    options.max_files = 9;
    node::BlockCollector collector{options};
    auto now{START};
    uint64_t max_seen_bytes{0};
    for (int64_t id{1}; id <= 12; ++id) { // reconnects reset per-connection bookkeeping
        collector.AddPeer(id, "198.51.100.7:1", "/btcd:0.24.2/", true, true);
        for (int round{0}; round < 6; ++round) {
            now += options.interval;
            const auto request{collector.NextRequest(id, now)};
            if (!request) continue;
            const auto index{size_t(std::find(targets.begin(), targets.end(), request->hash) - targets.begin())};
            for (uint8_t variant{0}; variant < 10; ++variant) { // more variants than the per-connection bound
                auto bytes{blocks[index]};
                bytes.back() = variant;
                collector.ReceiveBlock(id, bytes);
                BOOST_REQUIRE(collector.WaitForWrites(30s));
                collector.ReceiveBlock(id, bytes); // exact repeat
                max_seen_bytes = std::max(max_seen_bytes, ArchiveBytes(options.directory));
            }
        }
        collector.RemovePeer(id);
    }
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    const auto stats{collector.GetStats()};
    BOOST_CHECK_LE(max_seen_bytes, options.max_bytes);
    BOOST_CHECK_LE(stats.files, options.max_files);
    BOOST_CHECK_EQUAL(stats.bytes, ArchiveBytes(options.directory));
    BOOST_CHECK(!stats.paused.empty() || stats.dropped_responses > 0);
}

BOOST_AUTO_TEST_CASE(event_log_never_exceeds_budget)
{
    const auto targets{Targets(64)};
    auto options{MakeOptions(m_path_root / "logcap", targets)};
    options.max_log_bytes = 16 * 1024;
    node::BlockCollector collector{options};
    auto now{START};
    for (int64_t id{1}; id <= 200; ++id) {
        collector.AddPeer(id, "[2001:db8::1]:8333", "/btcd:0.24.2/" + std::string(200, 'x'), true, true);
        now += options.interval;
        if (const auto request{collector.NextRequest(id, now)}) collector.NotFound(id, {*request});
        collector.RemovePeer(id);
        BOOST_REQUIRE_LE(fs::file_size(options.directory / "events.jsonl"), options.max_log_bytes);
    }
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().log_bytes, fs::file_size(options.directory / "events.jsonl"));
    BOOST_CHECK(collector.GetStats().paused.empty()); // Optional negative survey logs cannot block captures.
}

BOOST_AUTO_TEST_CASE(eviction_preference_is_soft_and_expires)
{
    // Drive the real CConnman::AttemptToEvictConnection. Peers 0-19 are protected
    // by Core's own rules (netgroup, ping, transactions, blocks); 20-23 are not.
    NetGroupManager netgroupman{NetGroupManager::NoAsmap()};
    AddrMan addrman{netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0x1337, 0x1337, addrman, netgroupman, Params()};
    std::vector<CNode*> nodes;
    for (NodeId id{0}; id < 24; ++id) {
        SetMockTime(std::chrono::seconds{1'700'000'000 + id}); // Higher ids are younger connections.
        const uint64_t netgroup{id < 4 ? uint64_t(1000 + id) : 1};
        auto* node{new CNode{id, /*sock=*/nullptr, CAddress{LookupNumeric(strprintf("10.0.0.%d", id + 1), 8333), NODE_NONE},
                             netgroup, /*nLocalHostNonceIn=*/0, CAddress{}, /*addrNameIn=*/"", ConnectionType::INBOUND,
                             /*inbound_onion=*/false, /*network_key=*/1}};
        if (id >= 4 && id < 12) node->m_min_ping_time = std::chrono::milliseconds{id};
        if (id >= 12 && id < 16) node->m_last_tx_time = std::chrono::seconds{1'700'000'000 + id};
        if (id >= 16 && id < 20) node->m_last_block_time = std::chrono::seconds{1'700'000'000 + id};
        connman.AddTestNode(*node);
        nodes.push_back(node);
    }
    SetMockTime(0s);
    const auto steady_ms{[] { return Millis(SteadyClock::now()); }};
    const auto evict{[&]() -> std::optional<NodeId> {
        if (!connman.AttemptToEvictConnectionPublic()) return std::nullopt;
        std::optional<NodeId> evicted;
        for (auto* node : nodes) {
            if (node->fDisconnect) evicted = node->GetId();
            node->fDisconnect = false;
        }
        return evicted;
    }};
    BOOST_CHECK(evict() == NodeId{23}); // Ordinary choice: youngest unprotected peer.
    nodes[23]->m_blockcollector_protect_until_ms = steady_ms() + 60'000;
    BOOST_CHECK(evict() == NodeId{22}); // A pending archival request moves eviction elsewhere.
    nodes[23]->m_blockcollector_protect_until_ms = steady_ms() - 1;
    BOOST_CHECK(evict() == NodeId{23}); // The preference expires with the deadline.
    for (NodeId id{20}; id < 24; ++id) nodes[id]->m_blockcollector_protect_until_ms = steady_ms() + 60'000;
    BOOST_CHECK(evict() == NodeId{23}); // No ordinary alternative: fall back, ceiling kept.
    connman.ClearTestNodes();
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(blockcollector_findings_tests, BasicTestingSetup)

// Finding: connection churn by claimed btcd peers exhausts the persistent
// event-log budget and pauses all collection for this and later runs.
BOOST_AUTO_TEST_CASE(connection_churn_must_not_stop_collection)
{
    auto options{MakeOptions(m_path_root / "churn", Targets(1))};
    options.max_log_bytes = 1024 * 1024; // Smallest -blockcollectorloglimit.
    node::BlockCollector collector{options};
    const std::string agent{"/btcd:0.24.2/" + std::string(256 - 13, 'x')}; // MAX_SUBVERSION_LENGTH
    const std::string address{"[2001:db8:1234:5678:9abc:def0:1234:5678]:65535"};
    const auto initial_bytes{collector.GetStats().log_bytes};
    int64_t id{0};
    while (id < 256 && collector.GetStats().paused.empty()) {
        collector.AddPeer(id, address, agent, true, true);
        collector.RemovePeer(id++);
    }
    BOOST_CHECK_EQUAL(id, 256);
    BOOST_CHECK_EQUAL(collector.GetStats().log_bytes, initial_bytes);
    BOOST_CHECK_EQUAL(collector.GetStats().peers, 0);
    BOOST_CHECK_EQUAL(collector.GetStats().ignored_connections, 256);
    collector.AddPeer(id, "127.0.0.1:1", "/btcd:0.24.2/", true, true);
    BOOST_CHECK_MESSAGE(collector.NextRequest(id, START), "a peer that never received a request stopped collection");
}

// Finding: a peer that never answers keeps renewing the eviction preference.
BOOST_AUTO_TEST_CASE(unresponsive_peer_must_not_hold_protection_indefinitely)
{
    auto options{MakeOptions(m_path_root / "protection", Targets(1000))};
    node::BlockCollector collector{options}; // Default interval, timeout and pending limits.
    collector.AddPeer(1, "198.51.100.1:1", "/btcd:0.24.2/", true, true); // never answers
    collector.AddPeer(2, "203.0.113.2:2", "/btcd:0.24.2/", true, true);  // answers immediately
    int protected_steps{0};
    constexpr int STEPS{6000}; // Ten minutes in 100 ms message-handler iterations.
    for (int step{0}; step < STEPS; ++step) {
        const auto now{START + step * 100ms};
        collector.NextRequest(1, now);
        if (const auto request{collector.NextRequest(2, now)}) collector.NotFound(2, {*request});
        protected_steps += collector.ProtectionDeadline(1) > Millis(now);
    }
    const double unresponsive{double(protected_steps) / STEPS};
    BOOST_CHECK_MESSAGE(unresponsive <= 0.5, "an unresponsive peer was preferred for most of ten minutes");
}

// Finding: one connection can fill the global archive budget with distinct
// bodies under authentic headers, pausing collection from every other peer.
BOOST_AUTO_TEST_CASE(one_connection_must_not_exhaust_archive_budget)
{
    std::vector<std::vector<unsigned char>> blocks;
    std::vector<uint256> targets;
    for (uint8_t i{0}; i < 8; ++i) {
        blocks.push_back(Payload(60 + i, 1'000'000));
        targets.push_back(HeaderHash(blocks.back()));
    }
    auto options{MakeOptions(m_path_root / "monopoly", targets)};
    options.max_bytes = 16 * 1024 * 1024;
    node::BlockCollector collector{options};
    collector.AddPeer(1, "198.51.100.1:1", "/btcd:0.24.2/", true, true); // spoofs authentic headers
    collector.AddPeer(2, "203.0.113.2:2", "/btcd:0.24.2/", true, true);  // honest; has nothing
    size_t honest_queries{0};
    for (int step{0}; step < 400; ++step) {
        const auto now{START + step * 100ms};
        if (const auto request{collector.NextRequest(1, now)}) {
            const auto index{size_t(std::find(targets.begin(), targets.end(), request->hash) - targets.begin())};
            for (uint8_t variant{1}; variant <= 4; ++variant) {
                auto bytes{blocks[index]};
                bytes.back() = variant;
                collector.ReceiveBlock(1, bytes);
                BOOST_REQUIRE(collector.WaitForWrites(30s));
            }
        }
        if (const auto request{collector.NextRequest(2, now)}) {
            ++honest_queries;
            collector.NotFound(2, {*request});
        }
    }
    BOOST_CHECK_MESSAGE(honest_queries == targets.size(), "one connection's responses stopped the honest peer's survey");
}

// Finding: unanswered requests occupy the global pending budget for the full
// timeout, so a few silent connections throttle every responsive peer.
BOOST_AUTO_TEST_CASE(silent_peers_must_not_starve_responsive_peer)
{
    const auto run{[&](int silent_peers, const std::string& name) {
        auto options{MakeOptions(m_path_root / fs::PathFromString(name), Targets(2000))};
        node::BlockCollector collector{options}; // Defaults: 2 s, 100 ms, 30 s, 16 pending.
        FastRandomContext rng{/*fDeterministic=*/true};
        std::vector<int64_t> ids;
        for (int64_t id{1}; id <= silent_peers; ++id) ids.push_back(id);
        const int64_t responsive{1000};
        ids.push_back(responsive);
        for (const auto id : ids) collector.AddPeer(id, "192.0.2.1:1", "/btcd:0.24.2/", true, true);
        size_t answered{0};
        for (int step{0}; step < 6000; ++step) {
            const auto now{START + step * 100ms};
            std::shuffle(ids.begin(), ids.end(), rng); // Core shuffles peers every iteration.
            for (const auto id : ids) {
                const auto request{collector.NextRequest(id, now)};
                if (request && id == responsive) {
                    collector.NotFound(id, {*request});
                    ++answered;
                }
            }
        }
        return answered;
    }};
    const auto alone{run(0, "alone")}, contended{run(16, "contended")};
    BOOST_CHECK_MESSAGE(contended * 2 >= alone, "silent connections cut a responsive peer's survey rate by more than half");
}

BOOST_AUTO_TEST_SUITE_END()
