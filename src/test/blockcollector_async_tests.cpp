// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <hash.h>
#include <node/blockcollector.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <fstream>
#include <future>
#include <set>
#include <string>
#include <vector>

#ifndef WIN32
#include <unistd.h>
#endif

namespace {
uint256 HeaderHash(const std::vector<unsigned char>& bytes) { return Hash(std::span{bytes}.first(80)); }

node::BlockCollector::Options Options(const fs::path& root, const std::vector<std::vector<unsigned char>>& blocks)
{
    fs::create_directories(root);
    node::BlockCollector::Options options;
    options.targets = root / "targets.txt";
    options.directory = root / "archive";
    options.randomize = false;
    options.interval = 10ms;
    options.global_interval = 5ms;
    std::ofstream file{options.targets.std_path()};
    for (const auto& block : blocks) file << HeaderHash(block).ToString() << '\n';
    return options;
}

std::string Read(const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    return {std::istreambuf_iterator<char>{file}, {}};
}

struct Gate {
    std::promise<void> entered, release;
    std::shared_future<void> permission{release.get_future().share()};
    std::atomic<bool> fired{false}, opened{false};
    void Before()
    {
        if (!fired.exchange(true)) {
            entered.set_value();
            permission.wait();
        }
    }
    void Open() { if (!opened.exchange(true)) release.set_value(); }
};

struct ReleaseGate {
    Gate& gate;
    ~ReleaseGate() { gate.Open(); }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(blockcollector_async_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blocked_storage_does_not_block_state_or_disconnects)
{
    const std::vector<unsigned char> raw(1000, 0x31);
    Gate gate;
    auto entered{gate.entered.get_future()};
    auto options{Options(m_path_root / "blocked", {raw})};
    options.before_write = [&] { gate.Before(); };
    node::BlockCollector collector{options};
    ReleaseGate release{gate}; // Always unblock before joining the writer.
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    BOOST_REQUIRE(entered.wait_for(5s) == std::future_status::ready);
    auto query{std::async(std::launch::async, [&] {
        const auto before{collector.GetStats()};
        const auto deadline{collector.ProtectionDeadline(1)};
        const auto captured{collector.ReceiveBlock(1, raw)};
        collector.RemovePeer(1);
        return before.pending == 1 && deadline > 0 && captured == HeaderHash(raw) && collector.GetStats().peers == 0;
    })};
    const auto status{query.wait_for(1s)};
    gate.Open(); // Even a failing implementation must let its test terminate.
    BOOST_CHECK(status == std::future_status::ready);
    BOOST_CHECK(query.get());
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().bytes, raw.size());
    BOOST_CHECK_EQUAL(collector.GetStats().queue_bytes, 0);
    BOOST_CHECK(Read(options.directory / "events.jsonl").find("capture_intent") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(queue_limits_apply_while_the_writer_is_stalled)
{
    const std::vector<unsigned char> a(1000, 0x32), b(1000, 0x33);
    Gate gate;
    auto entered{gate.entered.get_future()};
    auto options{Options(m_path_root / "queue", {a, b})};
    options.max_queue_items = 2;
    options.max_queue_bytes = 5 * 1024 * 1024;
    options.before_write = [&] { gate.Before(); };
    node::BlockCollector collector{options};
    ReleaseGate release{gate};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_REQUIRE(entered.wait_for(5s) == std::future_status::ready);
    BOOST_CHECK(collector.ReceiveBlock(1, a) == HeaderHash(a));
    auto variant{a};
    ++variant.back();
    BOOST_CHECK(collector.ReceiveBlock(1, variant) == HeaderHash(a));
    const auto stats{collector.GetStats()};
    BOOST_CHECK_EQUAL(stats.queue_items, 2);
    BOOST_CHECK_LE(stats.queue_bytes, options.max_queue_bytes);
    BOOST_CHECK_EQUAL(stats.responses, 1);
    BOOST_CHECK_EQUAL(stats.dropped_responses, 1);
    BOOST_CHECK(stats.paused.empty());
    BOOST_CHECK(!collector.NextRequest(1, now + 10ms));
    gate.Open();
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.NextRequest(1, now + 20ms));
    BOOST_CHECK(collector.ReceiveBlock(1, b) == HeaderHash(b));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 2);
    BOOST_CHECK_EQUAL(collector.GetStats().queue_items, 0);
}

BOOST_AUTO_TEST_CASE(exclusive_temporary_creation_preserves_existing_data)
{
    const std::vector<unsigned char> raw(100, 0x34);
    auto options{Options(m_path_root / "exclusive", {raw})};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256{}.Write(raw.data(), raw.size()).Finalize(digest.data());
    const auto temporary{options.directory / fs::PathFromString(HeaderHash(raw).ToString() + "-" + HexStr(digest) + ".bin.tmp")};
    std::ofstream{temporary.std_path()} << "previous interrupted data";
    BOOST_CHECK(collector.ReceiveBlock(1, raw) == HeaderHash(raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(Read(temporary), "previous interrupted data");
    BOOST_CHECK_EQUAL(collector.GetStats().paused, "cannot preserve block response");
}

BOOST_AUTO_TEST_CASE(late_variants_cannot_spend_a_pending_peers_reservation)
{
    const std::vector<unsigned char> a(1'000'000, 0x36), b(3'000'000, 0x37);
    const std::vector<unsigned char> header{a.begin(), a.begin() + 80};
    auto options{Options(m_path_root / "reservation", {a, b})};
    options.max_bytes = 16 * 1024 * 1024; // Per connection: 4 MiB.
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    const auto now{SteadyClock::time_point{} + 1s};
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_CHECK(collector.ReceiveBlock(1, header) == HeaderHash(a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.NextRequest(1, now + 10ms));
    BOOST_CHECK(collector.ReceiveBlock(1, a) == HeaderHash(a));
    BOOST_CHECK_EQUAL(collector.GetStats().dropped_responses, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 1);
    BOOST_CHECK(collector.ReceiveBlock(1, b) == HeaderHash(b));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 2);
    // A deferred payload can be admitted when the pending reservation is freed.
    BOOST_CHECK(collector.ReceiveBlock(1, a) == HeaderHash(a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 3);
    BOOST_CHECK_EQUAL(collector.GetStats().bytes, header.size() + a.size() + b.size());
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(durable_intent_survives_a_missing_final_receipt)
{
    if (geteuid() == 0) return;
    const std::vector<unsigned char> raw(1000, 0x35);
    auto options{Options(m_path_root / "journal", {raw})};
    const auto events{options.directory / "events.jsonl"};
    bool intent_before_payload{false};
    options.after_capture_intent = [&] {
        intent_before_payload = Read(events).find("capture_intent") != std::string::npos;
        for (const auto& entry : fs::directory_iterator(options.directory)) {
            intent_before_payload &= entry.path().extension() != ".bin" && entry.path().extension() != ".tmp";
        }
        fs::permissions(events, fs::perms::owner_read, fs::perm_options::replace);
    };
    {
        node::BlockCollector collector{options};
        collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
        BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
        BOOST_CHECK(collector.ReceiveBlock(1, raw) == HeaderHash(raw));
        BOOST_REQUIRE(collector.WaitForWrites(30s));
        BOOST_CHECK(intent_before_payload);
        BOOST_CHECK_EQUAL(collector.GetStats().files, 1);
        BOOST_CHECK_EQUAL(collector.GetStats().incomplete_captures, 1);
        BOOST_CHECK_EQUAL(collector.GetStats().paused, "cannot write event log");
    }
    fs::permissions(events, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    options.after_capture_intent = {};
    node::BlockCollector restarted{options};
    BOOST_CHECK_EQUAL(restarted.GetStats().files, 1);
    BOOST_CHECK_EQUAL(restarted.GetStats().bytes, raw.size());
    BOOST_CHECK_EQUAL(restarted.GetStats().incomplete_captures, 1);
    BOOST_CHECK(Read(events).find("unresolved_capture_intents\":1") != std::string::npos);
}
#endif

BOOST_AUTO_TEST_CASE(random_starts_cover_the_entire_allowlist_without_repeats)
{
    std::vector<std::vector<unsigned char>> blocks;
    for (int i{0}; i < 20; ++i) blocks.emplace_back(80, i);
    auto options{Options(m_path_root / "offsets", blocks)};
    options.randomize = true;
    node::BlockCollector collector{options};
    std::set<uint256> starts;
    auto now{SteadyClock::time_point{} + 1s};
    for (int64_t id{1}; id <= 100; ++id) {
        collector.AddPeer(id, "peer", "/btcd:0.26.2/", true, true);
        const auto request{collector.NextRequest(id, now)};
        BOOST_REQUIRE(request);
        starts.insert(request->hash);
        collector.NotFound(id, {*request});
        collector.RemovePeer(id);
        now += options.interval;
    }
    BOOST_CHECK_GT(starts.size(), 1);
    collector.AddPeer(101, "peer", "/btcd:0.26.2/", true, true);
    std::set<uint256> surveyed;
    for (size_t i{0}; i < blocks.size(); ++i) {
        const auto request{collector.NextRequest(101, now)};
        BOOST_REQUIRE(request);
        BOOST_CHECK(surveyed.insert(request->hash).second);
        collector.NotFound(101, {*request});
        now += options.interval;
    }
    BOOST_CHECK_EQUAL(surveyed.size(), blocks.size());
    BOOST_CHECK(!collector.NextRequest(101, now));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
}

BOOST_AUTO_TEST_SUITE_END()
