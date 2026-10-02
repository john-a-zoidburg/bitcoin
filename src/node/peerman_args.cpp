// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>
#include <util/strencodings.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace node {

void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    if (auto value{argsman.GetIntArg("-txsendrate")}) {
        options.tx_send_rate = uint32_t(std::clamp<int64_t>(*value, 1, 1000));
    }

    if (auto value{argsman.GetBoolArg("-privatebroadcast")}) options.private_broadcast = *value;

    if (argsman.IsArgSet("-blockcollector") && !argsman.IsArgNegated("-blockcollector")) {
        const auto integer = [&](const char* name, int64_t fallback, int64_t minimum, int64_t maximum) {
            const auto value{ToIntegral<int64_t>(argsman.GetArg(name, std::to_string(fallback)))};
            if (!value) throw std::runtime_error(std::string{name} + " must be a whole number without units");
            if (*value < minimum || *value > maximum) throw std::runtime_error(std::string{name} + " is outside its permitted range");
            return *value;
        };
        const auto positive = [&](const char* name, int64_t fallback, int64_t maximum) {
            return integer(name, fallback, 1, maximum);
        };
        BlockCollector::Options collector;
        collector.targets = fsbridge::AbsPathJoin(argsman.GetDataDirNet(), argsman.GetPathArg("-blockcollector"));
        collector.directory = fsbridge::AbsPathJoin(argsman.GetDataDirNet(), argsman.GetPathArg("-blockcollectordir", fs::path{"block-archive"}));
        collector.user_agent = argsman.GetArg("-blockcollectoragent", "/btcd:");
        if (collector.user_agent.empty()) throw std::runtime_error("-blockcollectoragent must not be empty");
        if (argsman.GetArg("-blockcollector", "").empty()) throw std::runtime_error("-blockcollector requires a target filename");
        if (argsman.GetArg("-blockcollectordir", "block-archive").empty()) throw std::runtime_error("-blockcollectordir must not be empty");
        collector.interval = std::chrono::milliseconds{positive("-blockcollectorinterval", 2000, 3600000)};
        collector.global_interval = std::chrono::milliseconds{positive("-blockcollectorglobalinterval", 100, 3600000)};
        collector.timeout = std::chrono::milliseconds{positive("-blockcollectortimeout", 30000, 3600000)};
        collector.max_pending = positive("-blockcollectormaxpending", 16, 1024);
        collector.max_bytes = positive("-blockcollectormaxbytes", 1024, 1048576) * uint64_t{1024 * 1024};
        collector.max_files = positive("-blockcollectormaxfiles", 10000, 1000000);
        collector.max_log_bytes = positive("-blockcollectorloglimit", 64, 1048576) * uint64_t{1024 * 1024};
        collector.max_queue_bytes = positive("-blockcollectorqueue", 64, 1024) * uint64_t{1024 * 1024};
        collector.max_queue_items = positive("-blockcollectorqueueitems", 4096, 65536);
        collector.max_timeouts = positive("-blockcollectormaxtimeouts", 2, 1000);
        const auto peer_bytes{integer("-blockcollectorpeerbytes", 0, 0, 1048576)};
        collector.max_peer_bytes = static_cast<uint64_t>(peer_bytes) * 1024 * 1024;
        collector.randomize = argsman.GetBoolArg("-blockcollectorrandomize", true);
        options.block_collector = std::make_shared<BlockCollector>(std::move(collector));
    }
}

} // namespace node
