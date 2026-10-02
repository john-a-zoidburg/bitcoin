// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <hash.h>
#include <node/blockcollector.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <fstream>
#include <future>
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
    options.global_interval = 1ms;
    std::ofstream file{options.targets.std_path()};
    for (const auto& block : blocks) file << HeaderHash(block).ToString() << '\n';
    return options;
}

std::string Read(const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    return {std::istreambuf_iterator<char>{file}, {}};
}

std::string Filename(const std::vector<unsigned char>& bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(digest.data());
    return HeaderHash(bytes).ToString() + "-" + HexStr(digest) + ".bin";
}

struct Gate {
    std::promise<void> entered, release;
    std::shared_future<void> permission{release.get_future().share()};
    std::atomic<bool> active{false}, fired{false}, opened{false};
    void Before()
    {
        if (active && !fired.exchange(true)) {
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

BOOST_FIXTURE_TEST_SUITE(blockcollector_followup_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(negative_surveys_leave_room_for_capture_provenance)
{
    const std::vector<unsigned char> raw(1000, 0x41);
    auto options{Options(m_path_root / "survey-budget", {raw})};
    options.max_log_bytes = 64 * 1024;
    node::BlockCollector collector{options};
    auto now{SteadyClock::time_point{} + 1s};
    for (int64_t id{1}; id <= 200; ++id) {
        BOOST_REQUIRE(collector.AddPeer(id, "[2001:db8::1]:8333", "/btcd:0.26.2/" + std::string(200, 'x'), true, true));
        BOOST_REQUIRE(collector.NextRequest(id, now));
        collector.NotFound(id, {CInv{MSG_BLOCK, HeaderHash(raw)}});
        collector.RemovePeer(id);
        now += options.interval;
        BOOST_REQUIRE(collector.WaitForWrites(30s));
    }
    BOOST_CHECK(collector.GetStats().paused.empty());
    BOOST_CHECK_LE(collector.GetStats().survey_log_bytes, options.max_log_bytes / 4);
    BOOST_CHECK_LE(collector.GetStats().log_bytes, options.max_log_bytes / 4 + 4096); // Plus one essential start record.
    BOOST_CHECK_GT(collector.GetStats().dropped_events, 0);
    collector.AddPeer(201, "recoverable-peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(201, now));
    BOOST_REQUIRE(collector.ReceiveBlock(201, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(Read(options.directory / fs::PathFromString(Filename(raw))), std::string(raw.begin(), raw.end()));
    const auto journal{Read(options.directory / "events.jsonl")};
    BOOST_CHECK(journal.find("capture_intent") != std::string::npos);
    BOOST_CHECK(journal.find("block_response") != std::string::npos);
    BOOST_CHECK_LE(collector.GetStats().log_bytes, options.max_log_bytes);
}

BOOST_AUTO_TEST_CASE(long_negative_survey_has_bounded_summary_logging)
{
    std::vector<std::vector<unsigned char>> blocks;
    for (unsigned int i{0}; i < 1000; ++i) {
        blocks.emplace_back(80, 0x42);
        blocks.back()[0] = i & 0xff;
        blocks.back()[1] = i >> 8;
    }
    auto options{Options(m_path_root / "summary", blocks)};
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    auto now{SteadyClock::time_point{} + 1s};
    for (const auto& block : blocks) {
        BOOST_REQUIRE(collector.NextRequest(1, now));
        collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(block)}});
        now += options.interval;
    }
    collector.RemovePeer(1);
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().requests, blocks.size());
    BOOST_CHECK_EQUAL(collector.GetStats().notfound, blocks.size());
    BOOST_CHECK_LT(collector.GetStats().log_bytes, 4096);
    const auto journal{Read(options.directory / "events.jsonl")};
    BOOST_CHECK(journal.find("\"notfound\":1000") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(duplicate_reservation_backpressure_clears_after_draining)
{
    const std::vector<unsigned char> raw(1000, 0x43);
    Gate gate;
    auto entered{gate.entered.get_future()};
    auto options{Options(m_path_root / "duplicate-pressure", {raw})};
    options.max_files = 2;
    options.before_write = [&] { gate.Before(); };
    ASSERT_DEBUG_LOG("Block collector paused: archive limit reached");
    ASSERT_DEBUG_LOG("Block collector request capacity restored");
    node::BlockCollector collector{options};
    ReleaseGate release{gate};
    auto now{SteadyClock::time_point{} + 1s};
    for (int64_t id{1}; id <= 3; ++id) collector.AddPeer(id, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.NextRequest(2, now + 10ms));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    gate.active = true;
    BOOST_REQUIRE(collector.ReceiveBlock(2, raw));
    BOOST_REQUIRE(entered.wait_for(5s) == std::future_status::ready);
    BOOST_CHECK(!collector.NextRequest(3, now + 20ms));
    BOOST_CHECK_EQUAL(collector.GetStats().paused, "archive limit reached");
    gate.Open();
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.NextRequest(3, now + 30ms));
    BOOST_CHECK(collector.GetStats().paused.empty());
    BOOST_CHECK_EQUAL(collector.GetStats().duplicates, 1);
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 1);
}

BOOST_AUTO_TEST_CASE(integrity_conflict_preserves_incoming_and_outstanding_replies)
{
    const std::vector<unsigned char> a(1000, 0x44), b(1000, 0x45);
    auto options{Options(m_path_root / "conflict", {a, b})};
    fs::create_directories(options.directory);
    const auto damaged{options.directory / fs::PathFromString(Filename(a))};
    const std::string corrupt(a.size(), 'x');
    std::ofstream{damaged.std_path(), std::ios::binary} << corrupt;
    ASSERT_DEBUG_LOG("Block collector stopped new queries: existing archive file does not match response; incoming copy preserved");
    node::BlockCollector collector{options};
    const auto now{SteadyClock::time_point{} + 1s};
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_REQUIRE(collector.NextRequest(2, now + 10ms));
    collector.NotFound(2, {CInv{MSG_BLOCK, HeaderHash(a)}});
    BOOST_REQUIRE(collector.NextRequest(2, now + 20ms));
    BOOST_REQUIRE(collector.ReceiveBlock(1, a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK(!collector.GetStats().paused.empty());
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 1);
    BOOST_REQUIRE(collector.ReceiveBlock(2, b));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 3);
    BOOST_CHECK_EQUAL(collector.GetStats().dropped_responses, 0);
    BOOST_CHECK_EQUAL(Read(damaged), corrupt);
    BOOST_CHECK_EQUAL(Read(options.directory / fs::PathFromString(Filename(b))), std::string(b.begin(), b.end()));
    bool recovered{false};
    for (const auto& entry : fs::directory_iterator(options.directory)) {
        if (entry.path().extension() == ".bin" && entry.path() != damaged) recovered |= Read(entry.path()) == std::string(a.begin(), a.end());
    }
    BOOST_CHECK(recovered);
    const auto journal{Read(options.directory / "events.jsonl")};
    BOOST_CHECK(journal.find("conflicts_with") != std::string::npos);
    BOOST_CHECK(!collector.NextRequest(1, now + 30ms)); // Integrity failures still stop new queries.
}

BOOST_AUTO_TEST_CASE(late_response_updates_probe_counts_without_clearing_a_different_request)
{
    const std::vector<unsigned char> a(1000, 0x46), b(1000, 0x47);
    auto options{Options(m_path_root / "pending-counts", {a, b})};
    options.max_pending = 2;
    node::BlockCollector collector{options};
    auto now{SteadyClock::time_point{} + 1s};
    collector.AddPeer(1, "peer-a", "/btcd:0.26.2/", true, true);
    collector.AddPeer(2, "peer-b", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_CHECK(!collector.NextRequest(2, now + 10ms)); // Only one unproven probe.
    BOOST_CHECK(!collector.NextRequest(2, now + 10ms, /*can_send=*/false));
    now += options.timeout;
    BOOST_REQUIRE(collector.NextRequest(1, now)); // B is now pending on peer 1.
    collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(a)}}); // Late A response proves responsiveness.
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 1);
    BOOST_REQUIRE(collector.NextRequest(2, now + 10ms));
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 2);
    collector.NotFound(1, {CInv{MSG_BLOCK, HeaderHash(b)}});
    BOOST_REQUIRE(collector.ReceiveBlock(2, a));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 0);
    BOOST_CHECK_EQUAL(collector.GetStats().timeouts, 1);
    collector.AddPeer(3, "peer-c", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(3, now + 20ms));
    collector.RemovePeer(3);
    BOOST_CHECK_EQUAL(collector.GetStats().pending, 0);
    collector.AddPeer(4, "peer-d", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(4, now + 30ms));
}

BOOST_AUTO_TEST_CASE(survey_budget_and_capture_classification_survive_restart)
{
    const std::vector<unsigned char> raw(1000, 0x48);
    auto options{Options(m_path_root / "restart", {raw})};
    options.max_log_bytes = 32 * 1024;
    uint64_t previous_survey{0}, previous_log{0};
    auto now{SteadyClock::time_point{} + 1s};
    {
        node::BlockCollector collector{options};
        for (int64_t id{1}; id <= 100; ++id) {
            collector.AddPeer(id, "peer", "/btcd:0.26.2/", true, true);
            BOOST_REQUIRE(collector.NextRequest(id, now));
            collector.NotFound(id, {CInv{MSG_BLOCK, HeaderHash(raw)}});
            collector.RemovePeer(id);
            now += options.interval;
            BOOST_REQUIRE(collector.WaitForWrites(30s));
        }
        collector.AddPeer(101, "peer", "/btcd:0.26.2/", true, true);
        BOOST_REQUIRE(collector.NextRequest(101, now));
        BOOST_REQUIRE(collector.ReceiveBlock(101, raw));
        collector.RemovePeer(101);
        BOOST_REQUIRE(collector.WaitForWrites(30s));
        previous_survey = collector.GetStats().survey_log_bytes;
        previous_log = collector.GetStats().log_bytes;
        BOOST_CHECK_LT(previous_survey, previous_log);
    }
    node::BlockCollector restarted{options};
    BOOST_CHECK_EQUAL(restarted.GetStats().survey_log_bytes, previous_survey);
    BOOST_CHECK_LE(restarted.GetStats().survey_log_bytes, options.max_log_bytes / 4);
    BOOST_CHECK_GE(restarted.GetStats().log_bytes, previous_log);
    BOOST_CHECK(restarted.GetStats().paused.empty());
    restarted.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(restarted.NextRequest(1, now + 10ms));
    BOOST_REQUIRE(restarted.ReceiveBlock(1, raw));
    BOOST_REQUIRE(restarted.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(restarted.GetStats().duplicates, 1);
    BOOST_CHECK_EQUAL(restarted.GetStats().files, 1);
}

BOOST_AUTO_TEST_CASE(startup_record_and_warning_survive_an_exhausted_survey_allowance)
{
    const std::vector<unsigned char> raw(1000, 0x49);
    auto options{Options(m_path_root / "startup-quota", {raw})};
    options.max_log_bytes = 32 * 1024;
    fs::create_directories(options.directory);
    {
        std::ofstream prior{(options.directory / "events-old.jsonl").std_path()};
        for (int i{0}; i < 150; ++i) prior << "{\"event\":\"notfound\",\"padding\":\"" << std::string(80, 'x') << "\"}\n";
    }
    std::ofstream{(options.directory / "events.jsonl").std_path()} << "interrupted prior record";
    ASSERT_DEBUG_LOG("Block collector survey metadata allowance reached");
    node::BlockCollector collector{options};
    const auto journal{Read(options.directory / "events.jsonl")};
    UniValue start;
    BOOST_REQUIRE(start.read(journal));
    BOOST_CHECK_EQUAL(start["event"].get_str(), "start");
    BOOST_REQUIRE(start["previous_incomplete_log"].isStr());
    BOOST_CHECK_EQUAL(Read(options.directory / fs::PathFromString(start["previous_incomplete_log"].get_str())), "interrupted prior record");
    BOOST_CHECK_GT(collector.GetStats().survey_log_bytes, options.max_log_bytes / 4);
    BOOST_CHECK(collector.GetStats().paused.empty());
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 1);
    BOOST_CHECK_LE(collector.GetStats().log_bytes, options.max_log_bytes);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(startup_checks_journal_writability_even_when_survey_metadata_is_full)
{
    if (geteuid() == 0) return;
    const std::vector<unsigned char> raw(1000, 0x4a);
    auto options{Options(m_path_root / "startup-readonly", {raw})};
    options.max_log_bytes = 32 * 1024;
    fs::create_directories(options.directory);
    const auto events{options.directory / "events.jsonl"};
    {
        std::ofstream previous{events.std_path()};
        for (int i{0}; i < 150; ++i) previous << "{\"event\":\"notfound\",\"padding\":\"" << std::string(80, 'x') << "\"}\n";
    }
    fs::permissions(events, fs::perms::owner_read, fs::perm_options::replace);
    BOOST_CHECK_EXCEPTION(node::BlockCollector{options}, std::runtime_error, [](const auto& error) {
        return std::string{error.what()}.starts_with("Cannot initialize block collector journal: cannot write event log");
    });
    fs::permissions(events, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    node::BlockCollector restarted{options}; // A failed startup released the archive lock.
    BOOST_CHECK(restarted.GetStats().paused.empty());
}
#endif

BOOST_AUTO_TEST_CASE(post_rename_commit_failure_keeps_a_saved_payload_out_of_dropped_counts)
{
    const std::vector<unsigned char> raw(1000, 0x4b);
    auto options{Options(m_path_root / "directory-commit", {raw})};
    options.after_payload_rename = [] { throw std::runtime_error("cannot commit archive directory (directory fsync failed)"); };
    ASSERT_DEBUG_LOG("Block collector stopped new queries: cannot commit archive directory (directory fsync failed)");
    node::BlockCollector collector{options};
    collector.AddPeer(1, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, SteadyClock::time_point{} + 1s));
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    const auto stats{collector.GetStats()};
    BOOST_CHECK_EQUAL(stats.files, 1);
    BOOST_CHECK_EQUAL(stats.bytes, raw.size());
    BOOST_CHECK_EQUAL(stats.dropped_responses, 0);
    BOOST_CHECK_EQUAL(stats.incomplete_captures, 0);
    BOOST_CHECK_EQUAL(stats.paused, "cannot commit archive directory (directory fsync failed)");
    BOOST_CHECK_EQUAL(Read(options.directory / fs::PathFromString(Filename(raw))), std::string(raw.begin(), raw.end()));
    std::ifstream journal{(options.directory / "events.jsonl").std_path()};
    bool found{false};
    for (std::string line; std::getline(journal, line);) {
        UniValue event;
        BOOST_REQUIRE(event.read(line));
        if (event["event"].get_str() != "block_response") continue;
        found = true;
        BOOST_CHECK(event["saved"].get_bool());
        BOOST_CHECK(!event["storage_commits_succeeded"].get_bool());
        BOOST_CHECK(!event["directory_commit"].get_bool());
    }
    BOOST_CHECK(found);
}

BOOST_AUTO_TEST_CASE(startup_reports_the_log_budget_watermark)
{
    const std::vector<unsigned char> raw(1000, 0x4c);
    auto options{Options(m_path_root / "log-watermark", {raw})};
    options.max_log_bytes = 32 * 1024;
    fs::create_directories(options.directory);
    {
        std::ofstream previous{(options.directory / "events-old.jsonl").std_path()};
        for (int i{0}; i < 30; ++i) previous << "{\"event\":\"block_response\",\"capture_id\":\"older\",\"padding\":\"" << std::string(850, 'x') << "\"}\n";
    }
    ASSERT_DEBUG_LOG("Block collector event log is at least 80% full");
    node::BlockCollector collector{options};
    BOOST_CHECK_GE(collector.GetStats().log_bytes, options.max_log_bytes * 4 / 5);
    BOOST_CHECK_LE(collector.GetStats().log_bytes, options.max_log_bytes);
    BOOST_CHECK_EQUAL(collector.GetStats().survey_log_bytes, 0);
}

BOOST_AUTO_TEST_CASE(debounced_capacity_notice_eventually_reports_the_final_pause)
{
    const std::vector<unsigned char> raw(1000, 0x4d);
    auto variant{raw};
    ++variant.back();
    Gate gate;
    auto entered{gate.entered.get_future()};
    auto options{Options(m_path_root / "debounced-pause", {raw})};
    options.max_files = 2;
    options.before_write = [&] { gate.Before(); };
    const auto now{SteadyClock::time_point{} + 1s};
    node::BlockCollector* pointer{nullptr};
    std::promise<bool> sent, paused;
    auto sent_result{sent.get_future()}, paused_result{paused.get_future()};
    size_t pause_count{0};
    bool restored{false};
    DebugLogHelper notices{"Block collector", [&](const std::string* line) {
        if (!line) return false;
        if (line->find("Block collector paused: archive limit reached") != std::string::npos && ++pause_count == 2) paused.set_value(true);
        if (!restored && line->find("Block collector request capacity restored") != std::string::npos) {
            restored = true;
            // Issue the variant on the writer's resume callback, before its
            // debounce window closes; no cross-thread scheduling is needed.
            const auto request{pointer->NextRequest(3, now + 30ms)};
            sent.set_value(request && pointer->ReceiveBlock(3, variant) == HeaderHash(raw));
        }
        return false; // Observe the complete sequence rather than its first match.
    }};
    node::BlockCollector collector{options};
    pointer = &collector;
    ReleaseGate release{gate};
    for (int64_t id{1}; id <= 3; ++id) collector.AddPeer(id, "peer", "/btcd:0.26.2/", true, true);
    BOOST_REQUIRE(collector.NextRequest(1, now));
    BOOST_REQUIRE(collector.ReceiveBlock(1, raw));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_REQUIRE(collector.NextRequest(2, now + 10ms));
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    gate.active = true;
    BOOST_REQUIRE(collector.ReceiveBlock(2, raw));
    BOOST_REQUIRE(entered.wait_for(5s) == std::future_status::ready);
    gate.Open();
    BOOST_REQUIRE(sent_result.wait_for(5s) == std::future_status::ready);
    BOOST_REQUIRE(sent_result.get());
    BOOST_REQUIRE(collector.WaitForWrites(30s));
    BOOST_CHECK_EQUAL(collector.GetStats().files, 2);
    BOOST_CHECK_EQUAL(collector.GetStats().paused, "archive limit reached");
    BOOST_CHECK(paused_result.wait_for(5s) == std::future_status::ready);
}

BOOST_AUTO_TEST_SUITE_END()
