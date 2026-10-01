// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKCOLLECTOR_H
#define BITCOIN_NODE_BLOCKCOLLECTOR_H

#include <protocol.h>
#include <random.h>
#include <sync.h>
#include <uint256.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/time.h>

#include <array>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace node {

/** Opt-in archival requests, independent of normal block download/validation. */
class BlockCollector {
public:
    struct Options {
        fs::path targets;
        fs::path directory;
        std::string user_agent{"/btcd:"};
        std::chrono::milliseconds interval{2000};
        std::chrono::milliseconds global_interval{100};
        std::chrono::milliseconds timeout{30000};
        size_t max_pending{16};
        uint64_t max_bytes{1024 * 1024 * 1024};
        size_t max_files{10000};
        uint64_t max_log_bytes{64 * 1024 * 1024};
        uint64_t max_queue_bytes{64 * 1024 * 1024};
        size_t max_queue_items{4096};
        uint64_t max_peer_bytes{0}; //!< Zero derives a quarter of the archive allowance, at least one protocol payload.
        size_t max_timeouts{2};
        bool randomize{true};
        /** Optional storage instrumentation. Called only on the writer thread, without state locks. */
        std::function<void()> before_write;
        std::function<void()> after_capture_intent;
        std::function<void()> after_payload_rename;
    };

    struct Stats {
        bool enabled{false};
        std::string paused;
        size_t targets{0};
        size_t peers{0};
        size_t pending{0};
        uint64_t requests{0};
        uint64_t responses{0};
        uint64_t notfound{0};
        uint64_t timeouts{0};
        uint64_t duplicates{0};
        uint64_t files{0};
        uint64_t bytes{0};
        uint64_t log_bytes{0};
        uint64_t survey_log_bytes{0};
        uint64_t survey_log_limit{0};
        size_t queue_items{0};
        uint64_t queue_bytes{0};
        size_t suspended_peers{0};
        uint64_t ignored_connections{0};
        uint64_t dropped_responses{0};
        uint64_t dropped_events{0};
        uint64_t incomplete_captures{0};
    };

    explicit BlockCollector(Options options);
    ~BlockCollector();
    bool AddPeer(int64_t id, const std::string& address, const std::string& subver, bool inbound, bool witness) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void RemovePeer(int64_t id) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    std::optional<CInv> NextRequest(int64_t id, SteadyClock::time_point now, bool can_send = true) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void NotFound(int64_t id, const std::vector<CInv>& inventory) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Return the matching requested header hash. Stored bytes have NOT been validated. */
    std::optional<uint256> ReceiveBlock(int64_t id, std::span<const unsigned char> bytes) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    int64_t ProtectionDeadline(int64_t id) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    Stats GetStats() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Wait for queued persistence, for offline tools/tests only. Never call from networking or RPC. */
    bool WaitForWrites(std::chrono::milliseconds timeout = std::chrono::seconds{5}) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Peer {
        std::string address;
        std::string subver;
        bool witness{false};
        bool can_send{true};
        bool responsive{false};
        size_t offset{0};
        size_t cursor{0};
        size_t consecutive_timeouts{0};
        uint64_t notfound{0};
        uint64_t timeouts{0};
        uint64_t responses{0};
        std::vector<bool> requested;
        std::vector<bool> answered;
        std::map<size_t, std::vector<std::array<unsigned char, 32>>> response_hashes;
        std::optional<size_t> pending;
        SteadyClock::time_point deadline{};
        SteadyClock::time_point next_request{};
    };

    struct Budget {
        uint64_t bytes{0}; //!< Persisted plus queued bytes attributed to this connection.
        size_t files{0};
        size_t queued{0};
        bool connected{true};
    };

    struct Work {
        std::string event;
        std::vector<unsigned char> bytes;
        std::string filename;
        int64_t peer_id{0};
        uint64_t log_reserved{0};
        uint64_t memory_reserved{0};
        bool survey{false};
    };

    struct WriteResult {
        uint64_t bytes{0};
        size_t files{0};
        bool duplicate{false};
        bool dropped{false};
        bool dropped_event{false};
        bool incomplete_capture{false};
        std::string error;
    };

    static constexpr uint64_t RECEIPT_RESERVE{8192};
    UniValue Event(const std::string& type, int64_t id, const Peer& peer, std::optional<size_t> target = {}) const;
    bool QueueEvent(const UniValue& event) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool Queue(Work work) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Pause(const std::string& reason) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void UpdatePause() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void ClearPending(Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void MarkResponsive(Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool PeerHasBudget(int64_t id) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool PeerReady(int64_t id, const Peer& peer, SteadyClock::time_point now) const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    std::optional<int64_t> NextReadyPeer(SteadyClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Writer() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Persist(const Work& work, WriteResult& result) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool Append(const UniValue& event, bool survey = false) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct ArchiveLock;

    const Options m_options;
    const std::string m_run_id;
    const uint64_t m_peer_bytes;
    const size_t m_peer_files;
    mutable Mutex m_mutex;
    std::condition_variable_any m_cv;
    // Immutable after construction.
    std::vector<uint256> m_targets;
    std::map<uint256, size_t> m_target_index;
    std::unique_ptr<ArchiveLock> m_lock;
    std::map<int64_t, Peer> m_peers GUARDED_BY(m_mutex);
    std::map<int64_t, Budget> m_budgets GUARDED_BY(m_mutex);
    std::deque<Work> m_queue GUARDED_BY(m_mutex);
    FastRandomContext m_rng GUARDED_BY(m_mutex);
    std::optional<int64_t> m_last_scheduled_peer GUARDED_BY(m_mutex);
    std::optional<int64_t> m_next_ready_peer GUARDED_BY(m_mutex);
    SteadyClock::time_point m_next_request GUARDED_BY(m_mutex){};
    Stats m_stats GUARDED_BY(m_mutex);
    uint64_t m_reserved_bytes GUARDED_BY(m_mutex){0};
    size_t m_reserved_files GUARDED_BY(m_mutex){0};
    uint64_t m_reserved_log GUARDED_BY(m_mutex){0};
    uint64_t m_reserved_survey_log GUARDED_BY(m_mutex){0};
    size_t m_pending GUARDED_BY(m_mutex){0};
    size_t m_unproven_pending GUARDED_BY(m_mutex){0};
    std::string m_error GUARDED_BY(m_mutex);
    std::optional<std::string> m_pause_notice GUARDED_BY(m_mutex);
    bool m_survey_notice GUARDED_BY(m_mutex){false};
    bool m_survey_warned GUARDED_BY(m_mutex){false};
    bool m_log_notice GUARDED_BY(m_mutex){false};
    bool m_log_warned GUARDED_BY(m_mutex){false};
    bool m_capture_disabled GUARDED_BY(m_mutex){false};
    bool m_stopping GUARDED_BY(m_mutex){false};
    // Owned by the writer after startup, until joined during destruction.
    uint64_t m_disk_log_bytes{0};
    uint64_t m_disk_survey_log_bytes{0};
    uint64_t m_current_log_bytes{0};
    bool m_log_failed{false};
    std::thread m_writer;
};

} // namespace node

#endif // BITCOIN_NODE_BLOCKCOLLECTOR_H
