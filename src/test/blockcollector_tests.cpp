// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <net.h>
#include <node/blockcollector.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(blockcollector_tests, BasicTestingSetup)

static uint256 HeaderHash(const std::vector<unsigned char>& bytes)
{
    return Hash(std::span{bytes}.first(80));
}

static node::BlockCollector::Options CollectorOptions(const fs::path& root, const std::vector<std::vector<unsigned char>>& blocks)
{
    fs::create_directories(root);
    node::BlockCollector::Options options;
    options.randomize = false;
    options.targets = root / "targets.txt";
    options.directory = root / "archive";
    options.interval = 10ms;
    options.global_interval = 5ms;
    options.timeout = 20ms;
    options.max_pending = 2;
    std::ofstream file{options.targets.std_path()};
    for (const auto& block : blocks) file << HeaderHash(block).ToString() << '\n';
    return options;
}

BOOST_AUTO_TEST_CASE(peer_selection_pacing_and_timeouts)
{
    const std::vector<unsigned char> a(90, 0x11), b(100, 0x22);
    auto options{CollectorOptions(m_path_root / "pacing", {a, b})};
    node::BlockCollector collector{options};
    BOOST_CHECK(!collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", false, true));
    BOOST_CHECK(!collector.AddPeer(2, "peer-b", "/Satoshi:31.1.0/", true, true));
    BOOST_CHECK(collector.AddPeer(3, "peer-c", "/btcwire:0.5.0/btcd:0.24.2/", true, true));
    BOOST_CHECK(collector.AddPeer(4, "peer-d", "/btcd:0.23.0/", true, false));
    const auto now{SteadyClock::time_point{} + 1s};
    const auto request{collector.NextRequest(3, now)};
    BOOST_REQUIRE(request);
    BOOST_CHECK(request->hash == HeaderHash(a));
    BOOST_CHECK_EQUAL(request->type, MSG_WITNESS_BLOCK);
    BOOST_CHECK(!collector.NextRequest(4, now + 4ms));
    collector.NotFound(3, {CInv{MSG_WITNESS_BLOCK, HeaderHash(a)}});
    const auto legacy{collector.NextRequest(4, now + 5ms)};
    BOOST_REQUIRE(legacy);
    BOOST_CHECK_EQUAL(legacy->type, MSG_BLOCK);
    BOOST_CHECK(!collector.NextRequest(3, now + 6ms));
    collector.NotFound(3, {CInv{MSG_WITNESS_BLOCK, HeaderHash(a)}});
    BOOST_CHECK_EQUAL(collector.GetStats().notfound, 1);
    BOOST_CHECK(!collector.NextRequest(3, now + 9ms));
    const auto next{collector.NextRequest(3, now + 10ms)};
    BOOST_REQUIRE(next);
    BOOST_CHECK(next->hash == HeaderHash(b));
    BOOST_CHECK(!collector.NextRequest(4, now + 26ms, false));
    BOOST_CHECK_EQUAL(collector.GetStats().timeouts, 1);
    BOOST_CHECK_EQUAL(collector.ProtectionDeadline(4), 0);
    collector.RemovePeer(3);
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 0);
}

BOOST_AUTO_TEST_CASE(raw_preservation_late_responses_and_deduplication)
{
    // Deliberately not a valid block: archival must not depend on validation.
    const std::vector<unsigned char> raw(111, 0x33), unrelated(95, 0x44);
    auto options{CollectorOptions(m_path_root / "raw", {raw})};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_CHECK(!collector.ReceiveBlock(1, unrelated));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(raw)}});
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().bytes, raw.size());
    BOOST_REQUIRE(collector.NextRequest(2, now + 5ms));
    BOOST_REQUIRE(collector.ReceiveBlock(2, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().duplicates, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().files, 1);
    BOOST_CHECK(collector.GetStats().paused.empty());
    BOOST_CHECK_EQUAL(collector.GetStats().responses, 2);
    BOOST_REQUIRE(collector.ReceiveBlock(2, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().responses, 2);
    for (const auto& entry : fs::directory_iterator(options.directory)) {
        if (entry.path().extension() != ".bin") continue;
        std::ifstream file{entry.path(), std::ios::binary};
        const std::vector<unsigned char> stored{std::istreambuf_iterator<char>{file}, {}};
        BOOST_CHECK(stored == raw);
    }
}

BOOST_AUTO_TEST_CASE(storage_limits_and_corrupt_existing_file)
{
    const std::vector<unsigned char> a(90, 0x55), b(90, 0x66);
    auto options{CollectorOptions(m_path_root / "quota", {a, b})};
    options.max_files = 1;
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_REQUIRE(collector.ReceiveBlock(1, a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK(!collector.NextRequest(1, now + 10ms));
    BOOST_CHECK_EQUAL(collector.GetStats().paused, "archive limit reached");

    auto corrupt_options{CollectorOptions(m_path_root / "corrupt", {a})};
    node::BlockCollector corrupt{corrupt_options};
    corrupt.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    corrupt.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(corrupt.NextRequest(1, now));
    BOOST_REQUIRE(corrupt.ReceiveBlock(1, a));
    BOOST_REQUIRE(corrupt.WaitForWrites(30s));
    for (const auto& entry : fs::directory_iterator(corrupt_options.directory)) {
        if (entry.path().extension() == ".bin") {
            std::ofstream file{entry.path(), std::ios::binary | std::ios::trunc};
            const std::vector<unsigned char> changed(a.size(), 0x77);
            file.write(reinterpret_cast<const char*>(changed.data()), changed.size());
        }
    }
    BOOST_REQUIRE(corrupt.NextRequest(2, now + 5ms));
    BOOST_REQUIRE(corrupt.ReceiveBlock(2, a));
    BOOST_REQUIRE(corrupt.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(corrupt.GetStats().paused, "existing archive file does not match response; incoming copy preserved");
}

BOOST_AUTO_TEST_CASE(target_validation_and_pending_bound)
{
    const std::vector<unsigned char> a(80, 0x88), b(80, 0x99);
    auto options{CollectorOptions(m_path_root / "targets", {a, a, b})};
    options.max_pending = 1;
    node::BlockCollector collector{options};
    BOOST_CHECK_EQUAL(collector.GetStats().targets, 2);
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_CHECK(!collector.NextRequest(2, now + 5ms));
    collector.RemovePeer(1);
    BOOST_REQUIRE(collector.NextRequest(2, now + 5ms));
    auto invalid{CollectorOptions(m_path_root / "invalid", {a})};
    std::ofstream{invalid.targets.std_path()} << "not-a-block-hash\n";
    BOOST_CHECK_THROW(node::BlockCollector{invalid}, std::runtime_error);
    auto empty{CollectorOptions(m_path_root / "empty", {})};
    BOOST_CHECK_THROW(node::BlockCollector{empty}, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(partial_then_complete_and_variant_bound)
{
    const std::vector<unsigned char> complete(100, 0x12);
    const std::vector<unsigned char> header{complete.begin(), complete.begin() + 80};
    auto options{CollectorOptions(m_path_root / "variants", {complete})};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    BOOST_CHECK(!collector.ReceiveBlock(2, complete)); // Not requested from this connection.
    BOOST_REQUIRE(collector.ReceiveBlock(1, header));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.ReceiveBlock(1, complete));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 2);
    BOOST_CHECK_EQUAL(collector.GetStats().bytes, header.size() + complete.size());
    for (int i{0}; i < 5; ++i) {
        auto variant{complete};
        variant.back() = i;
        BOOST_REQUIRE(collector.ReceiveBlock(1, variant));
        BOOST_REQUIRE(collector.WaitForWrites(30s));
    }
    BOOST_CHECK_EQUAL(collector.GetStats().responses, 4);
    BOOST_CHECK_EQUAL(collector.GetStats().files, 4);
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 0);
}

BOOST_AUTO_TEST_CASE(round_robin_and_send_backpressure)
{
    const std::vector<unsigned char> a(90, 0x13), b(90, 0x14);
    auto options{CollectorOptions(m_path_root / "fairness", {a, b})};
    node::BlockCollector collector{options};
    for (int64_t id{1}; id <= 3; ++id) collector.AddPeer(id, "peer", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(a)}});
    // An earlier peer cannot consume every global slot, even if it answers fast.
    BOOST_CHECK(!collector.NextRequest(1, now + 10ms));
    BOOST_REQUIRE(collector.NextRequest(2, now + 10ms));
    collector.NotFound(2, {CInv{MSG_BLOCK, HeaderHash(a)}});
    BOOST_CHECK(!collector.NextRequest(1, now + 20ms));
    BOOST_CHECK(!collector.NextRequest(3, now + 20ms, false));
    BOOST_REQUIRE(collector.NextRequest(1, now + 20ms));
    collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(b)}});
    BOOST_REQUIRE(collector.NextRequest(2, now + 30ms));
    collector.NotFound(2, {CInv{MSG_BLOCK, HeaderHash(b)}});
    BOOST_REQUIRE(collector.NextRequest(3, now + 40ms, true));
}

BOOST_AUTO_TEST_CASE(archive_lock_is_exclusive_and_separate)
{
    const std::vector<unsigned char> raw(90, 0x15);
    auto options{CollectorOptions(m_path_root / "lock", {raw})};
    options.directory = options.targets.parent_path();
    const auto core_lock{options.directory / ".lock"};
    std::ofstream{core_lock.std_path()} << "Core lock sentinel";
    {
        node::BlockCollector first{options};
        BOOST_CHECK_THROW(node::BlockCollector{options}, std::runtime_error);
        BOOST_CHECK(fs::is_regular_file(options.directory / ".blockcollector.lock"));
        std::ifstream file{core_lock.std_path()};
        const std::string contents{std::istreambuf_iterator<char>{file}, {}};
        BOOST_CHECK_EQUAL(contents, "Core lock sentinel");
    }
    // Releasing a collector allows an ordinary restart in the same process.
    node::BlockCollector restarted{options};
    BOOST_CHECK(restarted.GetStats().enabled);
}

BOOST_AUTO_TEST_CASE(interrupted_files_and_log_are_preserved)
{
    const std::vector<unsigned char> raw(90, 0x16);
    auto options{CollectorOptions(m_path_root / "interrupted", {raw})};
    fs::create_directories(options.directory);
    const std::string torn_log{"{\"event\":\"unfinished"};
    std::ofstream{(options.directory / "events.jsonl").std_path()} << torn_log;
    std::ofstream{(options.directory / "partial.bin.tmp").std_path()} << "partial data";
    node::BlockCollector collector{options};
    const auto stats{collector.GetStats()};
    BOOST_CHECK_EQUAL(stats.files, 1);
    BOOST_CHECK_EQUAL(stats.bytes, 12);
    BOOST_CHECK_EQUAL(stats.paused, "incomplete archive files require inspection");
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_CHECK(!collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    size_t incomplete_logs{0};
    uint64_t total_log_bytes{0};
    for (const auto& entry : fs::directory_iterator(options.directory)) {
        if (entry.path().extension() != ".jsonl") continue;
        total_log_bytes += entry.file_size();
        std::ifstream file{entry.path()};
        const std::string contents{std::istreambuf_iterator<char>{file}, {}};
        if (entry.path().filename() != "events.jsonl") {
            ++incomplete_logs;
            BOOST_CHECK_EQUAL(contents, torn_log);
        } else {
            BOOST_CHECK(contents.ends_with('\n'));
            BOOST_CHECK(contents.find("previous_incomplete_log") != std::string::npos);
        }
    }
    BOOST_CHECK_EQUAL(incomplete_logs, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().log_bytes, total_log_bytes);
}

BOOST_AUTO_TEST_CASE(existing_log_budget_and_byte_reservation)
{
    const std::vector<unsigned char> raw(90, 0x17);
    auto options{CollectorOptions(m_path_root / "bytes", {raw})};
    options.max_bytes = MAX_PROTOCOL_MESSAGE_LENGTH;
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_CHECK(!collector.NextRequest(2, now + 5ms));
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK(!collector.NextRequest(2, now + 5ms));
    BOOST_CHECK_EQUAL(collector.GetStats().paused, "archive limit reached");

    auto log_options{CollectorOptions(m_path_root / "log-budget", {raw})};
    log_options.max_log_bytes = 4096;
    fs::create_directories(log_options.directory);
    std::ofstream{(log_options.directory / "events-old.jsonl").std_path()} << std::string(4096, '\n');
    node::BlockCollector log_collector{log_options};
    BOOST_CHECK_EQUAL(log_collector.GetStats().log_bytes, 4096);
    BOOST_CHECK_EQUAL(log_collector.GetStats().paused, "event log limit reached");
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(dangling_archive_symlinks_are_rejected)
{
    const std::vector<unsigned char> raw(90, 0x18);
    for (const auto* name : {"events.jsonl", ".blockcollector.lock", "response.bin", "response.tmp"}) {
        auto options{CollectorOptions(m_path_root / fs::PathFromString(name), {raw})};
        fs::create_directories(options.directory);
        fs::create_symlink(options.directory / "nonexistent", options.directory / name);
        BOOST_CHECK_THROW(node::BlockCollector{options}, std::runtime_error);
        BOOST_CHECK(!fs::exists(options.directory / "nonexistent"));
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
