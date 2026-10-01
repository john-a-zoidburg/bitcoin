// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockcollector.h>

#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <net.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/threadnames.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <mutex>
#include <set>
#include <stdexcept>
#include <utility>

#ifndef WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace node {
namespace {
using File = std::unique_ptr<FILE, decltype(&std::fclose)>;

// Unlike the best-effort DirectoryCommit helper, check failure here.
// Windows renames use MOVEFILE_WRITE_THROUGH instead.
void CommitDirectory(const fs::path& directory)
{
#ifndef WIN32
    File file{fsbridge::fopen(directory, "r"), &std::fclose};
    if (!file || fsync(fileno(file.get())) != 0) throw std::runtime_error("cannot commit archive directory (directory fsync failed)");
#endif
}

void RenameCommitted(const fs::path& source, const fs::path& destination)
{
#ifdef WIN32
    if (!MoveFileExW(source.wstring().c_str(), destination.wstring().c_str(), MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("cannot commit archive rename");
    }
#else
    fs::rename(source, destination);
    CommitDirectory(destination.parent_path());
#endif
}
} // namespace

struct BlockCollector::ArchiveLock {
    // POSIX record locks alone permit two holders in the same process.
    static inline std::mutex mutex;
    static inline std::set<fs::path> paths;
    fs::path path;
    std::unique_ptr<fsbridge::FileLock> file;

    explicit ArchiveLock(const fs::path& directory) : path{fs::canonical(directory) / ".blockcollector.lock"}
    {
        std::lock_guard guard{mutex};
        if (paths.contains(path)) throw std::runtime_error("Block collector archive is already in use");
        if (fs::is_symlink(path)) throw std::runtime_error("Invalid block collector lock file");
        if (!fs::exists(path)) {
            File created{fsbridge::fopen(path, "abx"), &std::fclose};
            if (!created && !fs::is_regular_file(path)) throw std::runtime_error("Cannot create block collector lock file");
        }
        if (!fs::is_regular_file(path)) throw std::runtime_error("Invalid block collector lock file");
        file = std::make_unique<fsbridge::FileLock>(path);
        if (!file->TryLock()) throw std::runtime_error("Block collector archive is already in use");
        paths.insert(path);
    }

    ~ArchiveLock()
    {
        std::lock_guard guard{mutex};
        file.reset();
        paths.erase(path);
    }
};

BlockCollector::BlockCollector(Options options)
    : m_options{std::move(options)},
      m_run_id{GetRandHash().ToString()},
      m_peer_bytes{m_options.max_peer_bytes ? m_options.max_peer_bytes : std::max<uint64_t>(MAX_PROTOCOL_MESSAGE_LENGTH, m_options.max_bytes / 4)},
      m_peer_files{std::max<size_t>(1, m_options.max_files / 4)}
{
    if (m_options.user_agent.empty()) throw std::runtime_error("Block collector user-agent filter must not be empty");
    if (m_options.interval.count() <= 0 || m_options.global_interval.count() <= 0 || m_options.timeout.count() <= 0 ||
        m_options.max_pending == 0 || m_options.max_pending > 1024 || m_options.max_timeouts == 0 ||
        m_options.max_bytes < MAX_PROTOCOL_MESSAGE_LENGTH || m_options.max_files == 0 || m_options.max_log_bytes < 4096 ||
        m_peer_bytes < MAX_PROTOCOL_MESSAGE_LENGTH || m_peer_bytes > m_options.max_bytes ||
        m_options.max_queue_bytes < MAX_PROTOCOL_MESSAGE_LENGTH + RECEIPT_RESERVE || m_options.max_queue_items < 2) {
        throw std::runtime_error("Invalid block collector limits");
    }
    if (!fs::is_regular_file(m_options.targets)) throw std::runtime_error("Block collector targets must be a regular file");
    std::ifstream targets{m_options.targets.std_path()};
    if (!targets) throw std::runtime_error("Cannot open block collector target file");
    if (fs::file_size(m_options.targets) > 8 * 1024 * 1024) throw std::runtime_error("Block collector target file is too large");
    std::string line;
    while (std::getline(targets, line)) {
        line = std::string{util::TrimStringView(line.substr(0, line.find('#')))};
        if (line.empty()) continue;
        if (line.size() != 64 || !IsHex(line)) throw std::runtime_error("Block collector targets must be 64-character block hashes");
        const auto hash{uint256::FromHex(line)};
        if (!hash || hash->IsNull()) throw std::runtime_error("Invalid block collector target hash");
        if (m_target_index.contains(*hash)) continue;
        if (m_targets.size() >= 100000) throw std::runtime_error("Too many block collector targets (maximum 100000)");
        m_target_index.emplace(*hash, m_targets.size());
        m_targets.push_back(*hash);
    }
    if (!targets.eof()) throw std::runtime_error("Cannot read block collector target file");
    if (m_targets.empty()) throw std::runtime_error("Block collector target file is empty");

    // Startup recovery is synchronous, before networking starts. Runtime archive
    // I/O belongs exclusively to the writer.
    fs::create_directories(m_options.directory);
    m_lock = std::make_unique<ArchiveLock>(m_options.directory);
    Stats stats;
    bool incomplete_files{false};
    std::set<std::string> intents, results;
    for (const auto& file : fs::directory_iterator{m_options.directory}) {
        if (file.path().extension() == ".bin" || file.path().extension() == ".tmp") {
            if (!file.is_regular_file() || file.is_symlink()) throw std::runtime_error("Invalid file in block collector archive");
            stats.bytes += file.file_size();
            ++stats.files;
            incomplete_files |= file.path().extension() == ".tmp";
        }
        if (file.path().filename().native().starts_with(fs::path{"events"}.native()) && file.path().extension() == ".jsonl") {
            if (!file.is_regular_file() || file.is_symlink()) throw std::runtime_error("Invalid block collector event log");
            m_disk_log_bytes += file.file_size();
            std::ifstream log{file.path(), std::ios::binary};
            while (std::getline(log, line)) {
                UniValue event;
                const bool parsed{event.read(line) && event.isObject() && event["event"].isStr()};
                const bool capture{parsed && (event["event"].get_str() == "capture_intent" || event["event"].get_str() == "block_response")};
                const bool start{parsed && event["event"].get_str() == "start"};
                if (!capture && !start) m_disk_survey_log_bytes += line.size() + (log.eof() ? 0 : 1);
                if (!capture || !event["capture_id"].isStr()) continue;
                if (event["event"].get_str() == "capture_intent") intents.insert(event["capture_id"].get_str());
                if (event["event"].get_str() == "block_response") results.insert(event["capture_id"].get_str());
            }
            if (!log.eof()) throw std::runtime_error("Cannot inspect block collector event log");
        }
    }
    for (const auto& result : results) intents.erase(result);
    stats.incomplete_captures = intents.size();
    const auto events{m_options.directory / "events.jsonl"};
    if (fs::is_symlink(events)) throw std::runtime_error("Invalid block collector event log");
    std::optional<std::string> recovered_log;
    if (fs::exists(events)) {
        if (!fs::is_regular_file(events)) throw std::runtime_error("Invalid block collector event log");
        m_current_log_bytes = fs::file_size(events);
        if (m_current_log_bytes > 0) {
            std::ifstream previous{events.std_path(), std::ios::binary};
            previous.seekg(-1, std::ios::end);
            const auto last{previous.get()};
            if (!previous) throw std::runtime_error("Cannot inspect block collector event log");
            previous.close();
            if (last != '\n') {
                for (size_t suffix{0}; ; ++suffix) {
                    recovered_log = "events-incomplete-" + m_run_id + "-" + std::to_string(suffix) + ".jsonl";
                    const auto destination{m_options.directory / fs::PathFromString(*recovered_log)};
                    if (fs::exists(destination) || fs::is_symlink(destination)) continue;
                    RenameCommitted(events, destination);
                    m_current_log_bytes = 0;
                    break;
                }
            }
        }
    }
    stats.enabled = true;
    stats.targets = m_targets.size();
    UniValue event{UniValue::VOBJ};
    event.pushKV("event", "start");
    event.pushKV("schema", 2);
    event.pushKV("run_id", m_run_id);
    event.pushKV("time", GetTime());
    event.pushKV("targets", uint64_t{m_targets.size()});
    event.pushKV("random_start_offsets", m_options.randomize);
    event.pushKV("survey_log_limit", m_options.max_log_bytes / 4);
    event.pushKV("unresolved_capture_intents", stats.incomplete_captures);
    event.pushKV("raw_responses_require_offline_validation", true);
    if (recovered_log) event.pushKV("previous_incomplete_log", *recovered_log);
    try {
        // Run metadata and a journal/directory-commit preflight are essential.
        // Only optional per-connection survey records use the survey quarter.
        Append(event);
    } catch (const std::exception& error) {
        if (m_log_failed) throw std::runtime_error(std::string{"Cannot initialize block collector journal: "} + error.what());
        // A full total log budget is a visible capacity pause, not an I/O error.
        stats.paused = error.what();
    }
    stats.log_bytes = m_disk_log_bytes;
    stats.survey_log_bytes = m_disk_survey_log_bytes;
    stats.survey_log_limit = m_options.max_log_bytes / 4;
    if (incomplete_files) stats.paused = "incomplete archive files require inspection";
    {
        LOCK(m_mutex);
        m_stats = std::move(stats);
        m_error = m_stats.paused;
        m_capture_disabled = m_log_failed;
        if (m_stats.survey_log_bytes >= m_stats.survey_log_limit) m_survey_warned = m_survey_notice = true;
        UpdatePause();
        if (!m_stats.paused.empty()) m_pause_notice = m_stats.paused;
    }
    m_writer = std::thread{[this] {
        util::ThreadRename("blkcollector");
        Writer();
    }};
}

BlockCollector::~BlockCollector()
{
    {
        LOCK(m_mutex);
        m_stopping = true;
    }
    m_cv.notify_all();
    if (m_writer.joinable()) m_writer.join();
}

void BlockCollector::Pause(const std::string& reason)
{
    // Core's file logger must not run under collector state locks either.
    if (m_stats.paused == reason) return;
    m_stats.paused = reason;
    // Preserve a pause reason when capacity is restored before the writer can
    // report it. Coalesce repeated transitions into a bounded pause/resume pair.
    if (!reason.empty() || !m_pause_notice) m_pause_notice = reason;
    m_cv.notify_all();
}

void BlockCollector::UpdatePause()
{
    if (!m_error.empty()) {
        Pause(m_error);
    } else if (m_pending == 0 &&
               (m_stats.bytes + m_reserved_bytes + MAX_PROTOCOL_MESSAGE_LENGTH > m_options.max_bytes ||
                m_stats.files + m_reserved_files + 1 > m_options.max_files)) {
        Pause("archive limit reached");
    } else if (m_pending == 0 && m_stats.log_bytes + m_reserved_log + RECEIPT_RESERVE > m_options.max_log_bytes) {
        Pause("event log limit reached");
    } else {
        Pause("");
    }
    if (!m_log_warned && m_stats.log_bytes >= m_options.max_log_bytes * 4 / 5) {
        m_log_warned = m_log_notice = true;
        m_cv.notify_all();
    }
}

bool BlockCollector::Append(const UniValue& event, bool survey)
{
    if (m_log_failed) throw std::runtime_error("cannot write event log");
    const std::string line{event.write() + "\n"};
    // Optional survey metadata may be omitted; run and capture provenance may
    // not. Survey records cannot consume more than a quarter of a fresh budget.
    if (survey && m_disk_survey_log_bytes + line.size() > m_options.max_log_bytes / 4) return false;
    if (line.size() > 4096 || line.size() > m_options.max_log_bytes || m_disk_log_bytes > m_options.max_log_bytes - line.size()) {
        throw std::runtime_error("event log limit reached");
    }
    const auto path{m_options.directory / "events.jsonl"};
    try {
        if (fs::is_symlink(path) || (fs::exists(path) && !fs::is_regular_file(path))) throw std::runtime_error("invalid event log");
        File file{fsbridge::fopen(path, "ab"), &std::fclose};
        if (!file || std::fwrite(line.data(), 1, line.size(), file.get()) != line.size() || !FileCommit(file.get())) {
            throw std::runtime_error("cannot write event log");
        }
        if (std::fclose(file.release()) != 0) throw std::runtime_error("cannot close event log");
        CommitDirectory(m_options.directory);
        m_disk_log_bytes += line.size();
        if (survey) m_disk_survey_log_bytes += line.size();
        m_current_log_bytes += line.size();
    } catch (const std::exception&) {
        m_log_failed = true;
        std::error_code error;
        const auto size{fs::file_size(path, error)};
        if (!error) {
            const auto growth{size > m_current_log_bytes ? size - m_current_log_bytes : 0};
            m_disk_log_bytes += growth;
            if (survey) m_disk_survey_log_bytes += growth;
            m_current_log_bytes = size;
        }
        throw;
    }
    return true;
}

UniValue BlockCollector::Event(const std::string& type, int64_t id, const Peer& peer, std::optional<size_t> target) const
{
    UniValue event{UniValue::VOBJ};
    event.pushKV("event", type);
    event.pushKV("run_id", m_run_id);
    event.pushKV("time", GetTime());
    event.pushKV("peer_id", id);
    event.pushKV("address", peer.address);
    event.pushKV("claimed_user_agent", peer.subver);
    if (target) event.pushKV("hash", m_targets[*target].ToString());
    return event;
}

bool BlockCollector::Queue(Work work)
{
    const uint64_t pending{uint64_t{m_pending}};
    const uint64_t memory{m_stats.queue_bytes + work.memory_reserved + pending * (MAX_PROTOCOL_MESSAGE_LENGTH + RECEIPT_RESERVE)};
    if (m_stopping || m_stats.queue_items + pending + 1 > m_options.max_queue_items || memory > m_options.max_queue_bytes) return false;
    const uint64_t log{m_stats.log_bytes + m_reserved_log + work.log_reserved + pending * RECEIPT_RESERVE};
    if (log > m_options.max_log_bytes) return false;
    if (work.survey && m_stats.survey_log_bytes + m_reserved_survey_log + work.log_reserved > m_options.max_log_bytes / 4) return false;
    // Commit counters only after deque allocation succeeds.
    m_queue.push_back(std::move(work));
    const auto& queued{m_queue.back()};
    m_reserved_log += queued.log_reserved;
    if (queued.survey) m_reserved_survey_log += queued.log_reserved;
    m_stats.queue_bytes += queued.memory_reserved;
    ++m_stats.queue_items;
    m_cv.notify_all(); // The writer and offline WaitForWrites callers share this condition variable.
    return true;
}

bool BlockCollector::QueueEvent(const UniValue& event)
{
    const auto encoded{event.write() + "\n"};
    if (encoded.size() > 4096 || !Queue(Work{.event = encoded, .log_reserved = encoded.size(), .memory_reserved = encoded.size() + 512, .survey = true})) {
        ++m_stats.dropped_events;
        if (!m_survey_warned && m_stats.survey_log_bytes + m_reserved_survey_log + encoded.size() > m_options.max_log_bytes / 4) {
            m_survey_warned = m_survey_notice = true;
            m_cv.notify_all();
        }
        return false;
    }
    return true;
}

bool BlockCollector::AddPeer(int64_t id, const std::string& address, const std::string& subver, bool inbound, bool witness)
{
    LOCK(m_mutex);
    if (!inbound || subver.find(m_options.user_agent) == std::string::npos || m_budgets.contains(id)) return false;
    m_budgets.emplace(id, Budget{});
    try {
        m_peers.emplace(id, Peer{.address = address, .subver = subver, .witness = witness,
                                .offset = m_options.randomize ? m_rng.randrange(m_targets.size()) : 0,
                                .requested = std::vector<bool>(m_targets.size()),
                                .answered = std::vector<bool>(m_targets.size())});
    } catch (...) {
        m_budgets.erase(id);
        throw;
    }
    // Request/capture records carry peer identity. Connection-only churn does not
    // consume persistent storage.
    m_next_ready_peer.reset();
    return true;
}

void BlockCollector::RemovePeer(int64_t id)
{
    LOCK(m_mutex);
    const auto it{m_peers.find(id)};
    if (it == m_peers.end()) return;
    auto event{Event("peer_disconnected", id, it->second, it->second.pending)};
    const auto queries{it->second.cursor};
    event.pushKV("queries_started", uint64_t{queries});
    event.pushKV("survey_offset", uint64_t{it->second.offset});
    event.pushKV("witness_requested", it->second.witness);
    event.pushKV("notfound", it->second.notfound);
    event.pushKV("timeouts", it->second.timeouts);
    event.pushKV("responses", it->second.responses);
    ClearPending(it->second);
    m_peers.erase(it);
    m_next_ready_peer.reset();
    auto& budget{m_budgets.at(id)};
    budget.connected = false;
    if (budget.queued == 0) m_budgets.erase(id);
    if (queries > 0) QueueEvent(event);
    else ++m_stats.ignored_connections;
    UpdatePause();
}

void BlockCollector::ClearPending(Peer& peer)
{
    if (!peer.pending) return;
    --m_pending;
    if (!peer.responsive) --m_unproven_pending;
    peer.pending.reset();
    m_next_ready_peer.reset();
    UpdatePause();
}

void BlockCollector::MarkResponsive(Peer& peer)
{
    if (!peer.responsive && peer.pending) --m_unproven_pending;
    peer.responsive = true;
    peer.consecutive_timeouts = 0;
    m_next_ready_peer.reset();
}

bool BlockCollector::PeerHasBudget(int64_t id) const
{
    const auto& budget{m_budgets.at(id)};
    return budget.bytes <= m_peer_bytes && m_peer_bytes - budget.bytes >= MAX_PROTOCOL_MESSAGE_LENGTH && budget.files < m_peer_files;
}

bool BlockCollector::PeerReady(int64_t id, const Peer& peer, SteadyClock::time_point now) const
{
    return peer.can_send && !peer.pending && peer.cursor < m_targets.size() && now >= peer.next_request &&
           peer.consecutive_timeouts < m_options.max_timeouts && PeerHasBudget(id) &&
           (peer.responsive || m_unproven_pending < std::max<size_t>(1, m_options.max_pending / 2));
}

std::optional<int64_t> BlockCollector::NextReadyPeer(SteadyClock::time_point now)
{
    if (m_next_ready_peer) {
        const auto it{m_peers.find(*m_next_ready_peer)};
        if (it != m_peers.end() && PeerReady(it->first, it->second, now)) return m_next_ready_peer;
        m_next_ready_peer.reset();
    }
    const auto start{m_last_scheduled_peer ? m_peers.upper_bound(*m_last_scheduled_peer) : m_peers.begin()};
    for (auto it{start}; it != m_peers.end(); ++it) if (PeerReady(it->first, it->second, now)) return m_next_ready_peer = it->first;
    for (auto it{m_peers.begin()}; it != start; ++it) if (PeerReady(it->first, it->second, now)) return m_next_ready_peer = it->first;
    return m_next_ready_peer;
}

std::optional<CInv> BlockCollector::NextRequest(int64_t id, SteadyClock::time_point now, bool can_send)
{
    LOCK(m_mutex);
    const auto it{m_peers.find(id)};
    if (it == m_peers.end()) return {};
    auto& peer{it->second};
    peer.can_send = can_send;
    if (peer.pending && now >= peer.deadline) {
        ClearPending(peer);
        ++peer.consecutive_timeouts;
        ++peer.timeouts;
        ++m_stats.timeouts;
    }
    if (!m_error.empty() || m_stopping || now < m_next_request || !PeerReady(id, peer, now)) return {};
    const size_t pending{m_pending};
    if (pending >= m_options.max_pending) return {};
    const uint64_t used_bytes{m_stats.bytes + m_reserved_bytes};
    const uint64_t reserved{uint64_t{pending + 1} * MAX_PROTOCOL_MESSAGE_LENGTH};
    if (used_bytes > m_options.max_bytes || reserved > m_options.max_bytes - used_bytes ||
        m_stats.files + m_reserved_files + pending + 1 > m_options.max_files) {
        UpdatePause();
        return {};
    }
    const uint64_t log{m_stats.log_bytes + m_reserved_log + uint64_t{pending + 1} * RECEIPT_RESERVE};
    if (log > m_options.max_log_bytes) {
        UpdatePause();
        return {};
    }
    if (m_stats.queue_items + pending + 2 > m_options.max_queue_items ||
        m_stats.queue_bytes + (pending + 1) * (MAX_PROTOCOL_MESSAGE_LENGTH + RECEIPT_RESERVE) + 4096 > m_options.max_queue_bytes) return {};
    if (NextReadyPeer(now) != id) return {};
    const size_t target{(peer.offset + peer.cursor) % m_targets.size()};
    // A first-query record and a disconnect summary replace per-target negative
    // records. Dropping optional survey metadata must not prevent recovery.
    if (peer.cursor == 0) {
        auto event{Event("request", id, peer, target)};
        event.pushKV("first_query_only", true);
        event.pushKV("witness_requested", peer.witness);
        event.pushKV("survey_offset", uint64_t{peer.offset});
        if (log + event.write().size() + 1 <= m_options.max_log_bytes) QueueEvent(event);
        else ++m_stats.dropped_events;
    }
    ++peer.cursor;
    peer.requested[target] = true;
    peer.pending = target;
    ++m_pending;
    if (!peer.responsive) ++m_unproven_pending;
    m_next_ready_peer.reset();
    peer.deadline = now + m_options.timeout;
    peer.next_request = now + m_options.interval;
    m_next_request = now + m_options.global_interval;
    m_last_scheduled_peer = id;
    ++m_stats.requests;
    UpdatePause();
    return CInv{peer.witness ? MSG_WITNESS_BLOCK : MSG_BLOCK, m_targets[target]};
}

void BlockCollector::NotFound(int64_t id, const std::vector<CInv>& inventory)
{
    LOCK(m_mutex);
    const auto it{m_peers.find(id)};
    if (it == m_peers.end()) return;
    auto& peer{it->second};
    for (const auto& inv : inventory) {
        if (inv.type != MSG_BLOCK && inv.type != MSG_WITNESS_BLOCK) continue;
        const auto target{m_target_index.find(inv.hash)};
        if (target == m_target_index.end() || !peer.requested[target->second] || peer.answered[target->second]) continue;
        peer.answered[target->second] = true;
        MarkResponsive(peer);
        if (peer.pending == target->second) ClearPending(peer);
        ++peer.notfound;
        ++m_stats.notfound;
    }
}

std::optional<uint256> BlockCollector::ReceiveBlock(int64_t id, std::span<const unsigned char> bytes)
{
    if (bytes.size() < 80 || bytes.size() > MAX_PROTOCOL_MESSAGE_LENGTH) return {};
    const uint256 hash{Hash(bytes.first(80))};
    const auto target{m_target_index.find(hash)};
    if (target == m_target_index.end()) return {};
    {
        LOCK(m_mutex);
        const auto it{m_peers.find(id)};
        if (it == m_peers.end() || !it->second.requested[target->second]) return {};
    }
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest;
    CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(digest.data());
    LOCK(m_mutex);
    const auto it{m_peers.find(id)};
    if (it == m_peers.end()) return hash;
    auto& peer{it->second};
    peer.answered[target->second] = true;
    MarkResponsive(peer);
    if (peer.pending == target->second) ClearPending(peer);
    const auto previous{peer.response_hashes.find(target->second)};
    if (previous != peer.response_hashes.end()) {
        if (std::find(previous->second.begin(), previous->second.end(), digest) != previous->second.end()) return hash;
        if (previous->second.size() >= 4) {
            ++m_stats.dropped_responses;
            return hash;
        }
    }
    if (m_stats.responses >= m_options.max_log_bytes / 1024 || m_capture_disabled || m_stopping) {
        ++m_stats.dropped_responses;
        return hash;
    }
    auto& budget{m_budgets.at(id)};
    const uint64_t peer_pending{peer.pending ? MAX_PROTOCOL_MESSAGE_LENGTH : 0};
    if (bytes.size() > m_peer_bytes || budget.bytes > m_peer_bytes - bytes.size() ||
        budget.bytes + bytes.size() + peer_pending > m_peer_bytes || budget.files + bool(peer.pending) + 1 > m_peer_files) {
        ++m_stats.dropped_responses;
        return hash;
    }
    const uint64_t used_bytes{m_stats.bytes + m_reserved_bytes};
    const uint64_t pending{uint64_t{m_pending}};
    if (bytes.size() > m_options.max_bytes || used_bytes > m_options.max_bytes - bytes.size() ||
        used_bytes + bytes.size() + pending * MAX_PROTOCOL_MESSAGE_LENGTH > m_options.max_bytes ||
        m_stats.files + m_reserved_files + pending + 1 > m_options.max_files) {
        ++m_stats.dropped_responses;
        return hash;
    }
    // Check queue capacity before copying a potentially large payload.
    if (m_stats.queue_items + pending + 1 > m_options.max_queue_items ||
        m_stats.queue_bytes + bytes.size() + RECEIPT_RESERVE + pending * (MAX_PROTOCOL_MESSAGE_LENGTH + RECEIPT_RESERVE) > m_options.max_queue_bytes) {
        ++m_stats.dropped_responses;
        return hash;
    }
    auto event{Event("block_response", id, peer, target->second)};
    const std::string filename{hash.ToString() + "-" + HexStr(digest) + ".bin"};
    event.pushKV("bytes", uint64_t{bytes.size()});
    event.pushKV("witness_requested", peer.witness);
    event.pushKV("sha256", HexStr(digest));
    event.pushKV("file", filename);
    event.pushKV("capture_id", m_run_id + "-" + std::to_string(id) + "-" + HexStr(digest));
    Work work{.event = event.write(), .bytes = {bytes.begin(), bytes.end()}, .filename = filename, .peer_id = id,
              .log_reserved = RECEIPT_RESERVE, .memory_reserved = bytes.size() + RECEIPT_RESERVE};
    // Allocate response bookkeeping before publishing work to the writer.
    // A failed deque allocation must leave all reservations unchanged.
    auto& variants{peer.response_hashes[target->second]};
    variants.push_back(digest);
    try {
        if (!Queue(std::move(work))) {
            variants.pop_back();
            if (variants.empty()) peer.response_hashes.erase(target->second);
            ++m_stats.dropped_responses;
            return hash;
        }
    } catch (...) {
        variants.pop_back();
        if (variants.empty()) peer.response_hashes.erase(target->second);
        throw;
    }
    ++m_stats.responses;
    ++peer.responses;
    m_reserved_bytes += bytes.size();
    ++m_reserved_files;
    budget.bytes += bytes.size();
    ++budget.files;
    ++budget.queued;
    UpdatePause();
    return hash;
}

void BlockCollector::Persist(const Work& work, WriteResult& result)
{
    UniValue event;
    if (!event.read(work.event)) {
        result.error = "invalid queued event";
        result.dropped = !work.bytes.empty();
        return;
    }
    if (m_log_failed) {
        result.error = "cannot write event log";
        result.dropped = !work.bytes.empty();
        return;
    }
    if (work.bytes.empty()) {
        try {
            result.dropped_event = !Append(event, /*survey=*/true);
        } catch (const std::exception& error) {
            result.error = error.what();
        }
        return;
    }
    auto intent{event};
    intent.pushKV("event", "capture_intent");
    // Name a possible conflict copy in the durable intent too, so a restart can
    // locate it even if the final result record is lost.
    const std::string conflict_name{work.filename.substr(0, work.filename.size() - 4) + "-conflict-" +
                                    m_run_id + "-" + std::to_string(work.peer_id) + ".bin"};
    intent.pushKV("conflict_file", conflict_name);
    try {
        Append(intent);
        result.incomplete_capture = true;
    } catch (const std::exception& error) {
        result.error = error.what();
        result.dropped = true;
        return;
    }
    fs::path destination{m_options.directory / fs::PathFromString(work.filename)};
    std::optional<fs::path> created_temporary;
    bool conflict{false};
    bool saved{false};
    try {
        if (m_options.after_capture_intent) m_options.after_capture_intent();
        if (fs::is_symlink(destination)) throw std::runtime_error("invalid existing archive file");
        if (fs::exists(destination)) {
            if (!fs::is_regular_file(destination)) throw std::runtime_error("invalid existing archive file");
            std::ifstream existing{destination.std_path(), std::ios::binary};
            // A damaged large file must not cause an unbounded duplicate read.
            std::vector<unsigned char> contents(work.bytes.size());
            existing.read(reinterpret_cast<char*>(contents.data()), contents.size());
            const bool equal{existing && existing.peek() == std::char_traits<char>::eof() && !existing.bad() && contents == work.bytes};
            if (equal) {
                result.duplicate = true;
                saved = true;
                event.pushKV("duplicate", true);
            } else {
                conflict = true;
                destination = m_options.directory / fs::PathFromString(conflict_name);
                if (fs::exists(destination) || fs::is_symlink(destination)) throw std::runtime_error("existing conflict copy must not be overwritten");
                event.pushKV("conflicts_with", work.filename);
                event.pushKV("file", conflict_name);
            }
        }
        if (!result.duplicate) {
            const fs::path temporary{destination + ".tmp"};
            File file{fsbridge::fopen(temporary, "wbx"), &std::fclose};
            if (!file) throw std::runtime_error("cannot create block response");
            created_temporary = temporary;
            if (std::fwrite(work.bytes.data(), 1, work.bytes.size(), file.get()) != work.bytes.size() || !FileCommit(file.get())) {
                throw std::runtime_error("cannot write block response");
            }
            if (std::fclose(file.release()) != 0) throw std::runtime_error("cannot close block response");
#ifdef WIN32
            RenameCommitted(temporary, destination);
#else
            fs::rename(temporary, destination);
#endif
            created_temporary.reset();
            result.files = 1;
            result.bytes = work.bytes.size();
            saved = true;
            if (m_options.after_payload_rename) m_options.after_payload_rename();
            CommitDirectory(m_options.directory);
        }
        event.pushKV("saved", true);
        event.pushKV("storage_commits_succeeded", true);
        if (conflict) result.error = "existing archive file does not match response; incoming copy preserved";
    } catch (const std::exception& error) {
        result.error = std::string{error.what()}.starts_with("cannot commit archive directory") ? error.what() : "cannot preserve block response";
        result.dropped = !saved;
        event.pushKV("saved", saved);
        event.pushKV("storage_commits_succeeded", false);
        if (saved) event.pushKV("directory_commit", false);
        event.pushKV("error", result.error);
        if (created_temporary) {
            std::error_code error;
            const auto size{fs::file_size(*created_temporary, error)};
            if (!error) {
                result.files = 1;
                result.bytes = size;
                event.pushKV("partial_file", fs::PathToString(created_temporary->filename()));
                event.pushKV("partial_bytes", size);
            }
        }
    }
    event.pushKV("persisted_time", GetTime());
    try {
        Append(event);
        result.incomplete_capture = false;
    } catch (const std::exception& error) {
        result.error = error.what();
        result.incomplete_capture = true;
    }
    return;
}

void BlockCollector::Writer()
{
    std::optional<SteadyClock::time_point> last_capacity_notice;
    std::optional<SteadyClock::time_point> capacity_retry_at;
    std::string last_capacity_state;
    bool capacity_warning_outstanding{false};
    WAIT_LOCK(m_mutex, lock);
    const auto refresh_capacity_notice = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        if (capacity_retry_at && (m_stopping || SteadyClock::now() >= *capacity_retry_at)) {
            m_pause_notice = m_stats.paused;
            capacity_retry_at.reset();
        }
    };
    while (true) {
        refresh_capacity_notice();
        while (m_queue.empty() && !m_pause_notice && !m_survey_notice && !m_log_notice && !m_stopping) {
            if (capacity_retry_at) m_cv.wait_until(lock, *capacity_retry_at);
            else m_cv.wait(lock);
            refresh_capacity_notice();
        }
        if (m_pause_notice || m_survey_notice || m_log_notice) {
            const auto pause{std::move(m_pause_notice)};
            m_pause_notice.reset();
            const bool resumed{pause && m_stats.paused.empty()};
            const bool terminal{!m_error.empty()};
            const bool stopping{m_stopping};
            const std::string capacity_state{m_stats.paused};
            const bool survey{std::exchange(m_survey_notice, false)};
            const bool log{std::exchange(m_log_notice, false)};
            {
                REVERSE_LOCK(lock, m_mutex);
                if (pause && terminal) {
                    // A capacity-notice storm must not consume the rate-limit
                    // allowance for an integrity or I/O failure.
                    LogWarning("Block collector stopped new queries: %s\n", *pause);
                    capacity_retry_at.reset();
                } else if (pause) {
                    if (!pause->empty() && (stopping || !last_capacity_notice || SteadyClock::now() - *last_capacity_notice >= 1s)) {
                        last_capacity_notice = SteadyClock::now();
                        LogWarning("Block collector paused: %s\n", *pause);
                        last_capacity_state = *pause;
                        capacity_warning_outstanding = true;
                    }
                    if (resumed && capacity_warning_outstanding) {
                        LogInfo("Block collector request capacity restored\n");
                        capacity_warning_outstanding = false;
                        last_capacity_state.clear();
                    }
                    // A suppressed transition must be postponed, not lost. Wake
                    // even without new jobs, and report the current state then.
                    if (capacity_state != last_capacity_state) capacity_retry_at = last_capacity_notice.value_or(SteadyClock::now()) + 1s;
                    else capacity_retry_at.reset();
                }
                if (survey) LogWarning("Block collector survey metadata allowance reached; further summaries may be omitted. Capture provenance remains eligible.\n");
                if (log) LogWarning("Block collector event log is at least 80%% full; inspect getblockcollectorinfo and preserve examined logs before rotation.\n");
            }
            continue;
        }
        if (m_queue.empty()) break;
        Work work{std::move(m_queue.front())};
        m_queue.pop_front();
        WriteResult result;
        {
            REVERSE_LOCK(lock, m_mutex);
            try {
                if (m_options.before_write) m_options.before_write();
                Persist(work, result);
            } catch (const std::exception&) {
                result.error = "archive worker failed";
                result.dropped = !work.bytes.empty() && result.files == 0;
            }
        }
        m_stats.files += result.files;
        m_stats.bytes += result.bytes;
        m_stats.log_bytes = m_disk_log_bytes;
        m_stats.survey_log_bytes = m_disk_survey_log_bytes;
        m_stats.duplicates += result.duplicate;
        m_stats.dropped_responses += result.dropped;
        m_stats.dropped_events += result.dropped_event;
        m_stats.incomplete_captures += result.incomplete_capture;
        m_reserved_log -= work.log_reserved;
        if (work.survey) m_reserved_survey_log -= work.log_reserved;
        m_stats.queue_bytes -= work.memory_reserved;
        --m_stats.queue_items;
        if (!work.bytes.empty()) {
            m_reserved_bytes -= work.bytes.size();
            --m_reserved_files;
            auto& budget{m_budgets.at(work.peer_id)};
            budget.bytes -= work.bytes.size();
            budget.bytes += result.bytes;
            --budget.files;
            budget.files += result.files;
            --budget.queued;
            if (!budget.connected && budget.queued == 0) m_budgets.erase(work.peer_id);
        }
        m_next_ready_peer.reset();
        m_capture_disabled = m_log_failed;
        if (!result.error.empty()) m_error = result.error;
        UpdatePause();
        m_cv.notify_all();
    }
}

bool BlockCollector::WaitForWrites(std::chrono::milliseconds timeout)
{
    WAIT_LOCK(m_mutex, lock);
    const auto deadline{SteadyClock::now() + timeout};
    while (m_stats.queue_items != 0) {
        if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) return m_stats.queue_items == 0;
    }
    return true;
}

int64_t BlockCollector::ProtectionDeadline(int64_t id) const
{
    LOCK(m_mutex);
    const auto it{m_peers.find(id)};
    if (it == m_peers.end() || !it->second.pending || it->second.consecutive_timeouts > 0 || !m_stats.paused.empty()) return 0;
    return std::chrono::duration_cast<std::chrono::milliseconds>(it->second.deadline.time_since_epoch()).count();
}

BlockCollector::Stats BlockCollector::GetStats() const
{
    LOCK(m_mutex);
    auto stats{m_stats};
    stats.peers = m_peers.size();
    stats.pending = m_pending;
    stats.suspended_peers = std::count_if(m_peers.begin(), m_peers.end(), [&](const auto& entry) EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        return entry.second.consecutive_timeouts >= m_options.max_timeouts || !PeerHasBudget(entry.first);
    });
    return stats;
}

} // namespace node
