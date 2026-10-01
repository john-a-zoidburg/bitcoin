# Historical block collector

The collector retrieves historical block-message payloads from peers that initiate
inbound connections. It requests an explicit allowlist of hashes using ordinary
`getdata` messages, including hashes whose headers are not locally indexed. By
default, it selects peers whose claimed user agent contains `/btcd:`; this string
is a selection hint, not authentication.

Research-only responses are archived without being submitted to chainstate or
relayed. If Core also requested the same block through its normal download path
from the same connection, normal validation still applies. **Archived payloads
may be incomplete or invalid.** Validate them offline before classifying or
publishing recovered blocks. Use the allowlist for research probes;
`getblockfrompeer` retains Core's normal validation behavior. A peer's own serving
policy determines whether it returns a requested block.

## Prepare the target list

The target file contains one nonzero, 64-character hexadecimal block hash per
line. Blank lines and `#` comments are allowed. Duplicate hashes are removed while
preserving order. Startup rejects an empty list, malformed hashes, a non-regular
file, a file larger than 8 MiB, or more than 100,000 unique hashes. The list is read
at startup; restart to change it. Preserve the exact ordered list with each run's
records, since the event log does not embed it.

To select missing bodies from a `bitcoin-data/stale-blocks` CSV:

```sh
python3 contrib/block-collector/make_targets.py \
    --csv /path/to/stale-blocks.csv \
    --blocks /path/to/validated-blocks \
    --output /path/to/targets.txt
```

Replace the example paths and create the output's parent directory first. Omit
`--blocks` to include all CSV hashes, or repeat it for multiple directories.
**Only supply directories of independently validated complete `.bin` bodies.**
Unvalidated collector captures must not be used to exclude recovery targets.

The helper checks complete transaction serialization and the header's transaction
Merkle root, rejects trailing bytes and duplicate-transaction Merkle mutation, and
requires the coinbase witness reserved value when a witness commitment is present.
It does not verify proof of work, the witness commitment itself, ancestry or
historical consensus rules. Rejected files remain recovery targets and are
counted in the summary printed to standard error. The output is replaced
atomically; it must be outside the body directories and separate from all inputs,
including hard links. New output files respect the process umask; replacements
preserve the existing permissions.

## Configure and start a dedicated node

Use an unpruned node with its own data directory and archive. If another Core
instance shares the host, use distinct local P2P and RPC ports. Complete initial
sync and any AssumeUTXO background validation before relying on discovery or
historical block service. btcd 0.24.2 requires its outbound peers to advertise
`NODE_NETWORK` and, after SegWit activation, witness support; full archival Core
provides these services automatically. Pruning and unfinished background
validation can prevent `NODE_NETWORK` advertisement.

Use a local archive filesystem that supports file commits and, on POSIX,
directory fsync. An archive lock prevents two collectors from sharing the same
directory. Journal or directory-commit failure during initialization aborts
startup; a full log budget instead starts the collector paused.

Mainnet example for the collector's `bitcoin.conf`:

```ini
disablewallet=1
blocksonly=1
listen=1
port=8333
prune=0
maxconnections=500
blockcollector=/path/to/targets.txt
blockcollectordir=/path/to/private-archive
```

Create the data directory, place the configuration there, and start this build:

```sh
bitcoind -datadir=/path/to/collector
```

Enabling `blockcollector` defaults to `blocksonly=1` and `maxconnections=500` unless
explicitly overridden. Relative target and archive paths use the network data
directory. `listen=0` prevents collection and produces a startup warning. Core's
file-descriptor checks, hard connection ceiling, bans and inbound diversity
protections still apply.

### Reachability and discovery

Make the mainnet P2P listener reachable on public TCP port 8333 and advertise the
correct routable endpoint. Forward that port to the collector when behind NAT;
`externalip=<public-address>:8333` can specify the advertised address but does not
create a port mapping. Setting `externalip` disables automatic address discovery
by default. btcd's default-port preference makes a public 8333 endpoint preferable
to a nonstandard port.

Once listening and past initial sync, Core announces its address to peers that
participate in address relay. Keep normal automatic peer discovery enabled.
`dnsseed` finds peers; it does not register this node with a DNS seed.
`maxconnections=500` increases capacity without increasing the eight automatic
full-relay outbound connections. Optional `addnode` connections can exchange
announcements with additional peers. `blocksonly=1` permits address relay;
transaction relay and optional filter services are not required by btcd 0.24.2.

Peer selection remains outside the collector's control. Address sharing is
sampled, and a btcd node using a fixed `--connect` list will not automatically
select a new collector. See btcd 0.24.2's [peer selection](https://github.com/btcsuite/btcd/blob/cc26860b40265e1332cca8748c5dbaf3c81cc094/server.go)
and [address manager](https://github.com/btcsuite/btcd/blob/cc26860b40265e1332cca8748c5dbaf3c81cc094/addrmgr/addrmanager.go)
for implementation details.

## Monitor collection

Direct all RPC commands to the collector's data directory:

```sh
bitcoin-cli -datadir=/path/to/collector getblockchaininfo
bitcoin-cli -datadir=/path/to/collector getnetworkinfo
bitcoin-cli -datadir=/path/to/collector getblockcollectorinfo
```

Before waiting for recoveries, check that initial sync is complete, local service
names include `NETWORK` and `WITNESS`, and the advertised endpoint is correct.
Verify reachability from outside the local network and look for inbound
connections. Absence from one random or cached `getaddr` response does not prove
a discovery failure.

Use `getblockcollectorinfo` to distinguish connectivity, progress and storage:

| Fields | Interpretation |
| --- | --- |
| `enabled`, `targets`, `peers` | Whether configured, target count, and connected matching inbound peers |
| `requests`, `pending`, `notfound`, `timeouts` | Survey activity; a timeout is not evidence that a block is absent |
| `responses`, `duplicates` | Payloads admitted for persistence and byte-identical responses already archived; neither is a unique-block count |
| `files`, `bytes`, `log_bytes` | Archive usage, including previous runs and interrupted writes |
| `queue_items`, `queue_bytes` | Queued and in-progress persistence work; not a durability confirmation |
| `survey_log_bytes`, `survey_log_limit` | Optional survey metadata usage and allowance |
| `suspended_peers` | Connections suspended after repeated timeouts or insufficient retention allowance |
| `dropped_responses`, `dropped_events` | Payload admission/persistence failures and omitted optional metadata |
| `incomplete_captures` | Capture intents without result records; inspect their named files |
| `paused` | Current reason new queries are paused, or an empty string |

Survey counters, including `notfound`, and duplicate/dropped/ignored counts reset
on restart. Archive totals and unresolved capture intents include prior runs. A
request that times out and later receives a reply increments both counters.
An empty `paused` value does not guarantee immediate requests: the collector may
be waiting for peers, pacing, queue space or per-connection allowances. Consult
RPC for current state; `debug.log` coalesces temporary pause/resume notices and
warns when the event log reaches 80% of its budget.

## Request scheduling and resource limits

The collector allows one outstanding request per connection, takes turns between
ready connections, and reserves space for a maximum protocol payload before each
request. Each target is queried at most once per matching connection, starting at
a random offset and wrapping through the list. Reconnection starts a new survey.
Use `blockcollectorrandomize=0` for a repeatable target order.

A timeout advances the survey without disconnecting the peer. After two
consecutive timeouts by default, that connection's survey is suspended. Late
requested replies remain eligible for capture and can restore responsiveness.
At most half the pending allowance, with a minimum of one, is assigned to
connections that have not answered. Pending requests receive a soft eviction
preference that expires at the timeout; unanswered requests remove the preference
until a matching reply arrives. Ordinary eviction applies if no alternative
candidate remains.

Archive limits cover previous runs' files and logs as well as new data. Reserve
storage separately for Core's chain data and other logs. Each connection
has a retention allowance of one quarter of the archive byte and file budgets,
with minimums of one maximum protocol payload and one file. Queued payloads count
towards these allowances; verified duplicates release their reservations.
`blockcollectorpeerbytes` overrides the byte allowance. These limits apply to
connections, not authenticated identities, so reconnecting or distributed sources
can still consume finite global budgets.

Runtime persistence and duplicate reads run on a dedicated writer thread without
blocking networking or status RPC on storage I/O. Queue limits include in-progress
work and outstanding response reservations. The memory allowance covers payload
and metadata accounting, not Core's receive buffers or total process memory.
Response bookkeeping also limits admitted payloads per run to one per configured
1,024 bytes of log capacity.

Optional survey records can consume at most one quarter of the log budget.
Further optional records are omitted and counted in `dropped_events`; queries and
captures can continue using the remaining capacity. Archived files and logs are
never automatically deleted. Capacity reserved by queued work is released as
that work finishes; new queries resume when enough space becomes available. Integrity or I/O errors
stop new queries until the cause is corrected and the node restarted. Already
requested replies can still be captured if budgets and the journal permit it;
a failed journal prevents further capture.

## Archive format and validation

Each response is saved as `BLOCKHASH-SHA256.bin`: BLOCKHASH is the header hash,
and SHA256 covers the exact received payload. Witness bytes are retained when
supplied. Identical responses from different peers share a file; distinct payloads
for the same header remain separate. Up to four distinct payloads per connection
and target can be processed, so an incomplete reply can be followed by a complete
one. Identical repeats on the same connection are ignored.

If an existing file differs from the incoming bytes, the original is retained and
the incoming payload is saved as `BLOCKHASH-SHA256-conflict-RUNID-PEERID.bin`.
The result records `conflicts_with`, and new queries pause for inspection. Both
files count against the archive budget.

`events.jsonl` records run metadata, the first query per connection, disconnect
summaries, and capture intents/results. Disconnect summaries contain aggregate
query, `notfound`, timeout and admitted-response counts, plus the starting offset.
Individual negative results are not logged. Connections that disconnect without
being queried increment `ignored_connections` without generating a log record.
Capture records contain their own provenance, independent of optional survey
records. **Logs contain peer addresses and claimed user agents. Keep them private;
publish recovered bytes with appropriately redacted provenance.**

The schema-2 journal commits a `capture_intent` before writing the payload and a
`block_response` result afterwards. Shared `run_id` and `capture_id` fields link
the records; each includes the block hash, payload SHA256 and filename. The intent
also names a possible conflict copy. Payloads are written to exclusive temporary
files, committed, and renamed into place. POSIX directory updates are committed;
Windows uses file commits and write-through rename. `storage_commits_succeeded`
reports the success of storage operations, not a guarantee against power loss.
A result with `saved:true` and `storage_commits_succeeded:false` means the file is
available for inspection but a commit operation failed. A directory-commit failure
is also reported as `directory_commit:false`; saved bytes remain counted.

Before contributing a recovered block, check its complete serialization, header
hash, proof of work, transaction Merkle root, witness commitment when applicable,
ancestry and historical consensus rules. Storage receipts and peer claims are
not consensus validation. Keep invalid, incomplete and validated stale recoveries
clearly distinguished.

## Stop, inspect and resume

Use an orderly shutdown so queued persistence finishes before the archive lock
is released:

```sh
bitcoin-cli -datadir=/path/to/collector stop
```

A hung storage call can delay shutdown even though networking and status RPC do
not wait for that I/O. Wait for the process to exit before modifying the archive.

After an interruption or storage error:

1. Preserve the archive, its ordered target list and available status information.
2. Inspect `.tmp` files, conflict copies and unresolved capture intents. Interrupted
   `.tmp` files remain counted and pause new queries after restart. Do not discard
   them before checking for recoverable bytes.
3. Correct the storage problem or adjust the relevant limits, preserving examined
   evidence separately when necessary, then restart. Restart alone does not free
   space occupied by retained data.

A torn final line in `events.jsonl` causes the old log to be preserved as
`events-incomplete-RUNID-N.jsonl` before a fresh log is opened. Preserved logs count
towards the log limit. An unresolved intent can name a saved file whose final
receipt was interrupted; inspect that file before declaring the capture lost.

To rotate examined logs, stop the node and preserve all `events*.jsonl` files in a
separate private archive before restarting with the same raw-data directory.
Keep intent/result pairs, run identifiers and reconciliation results together.
Moved logs no longer contribute to this directory's budget or restart
reconciliation. Never rotate an active journal or delete unexamined evidence.

## Configuration reference

All sizes below are MiB and all intervals are milliseconds. Options can be set in
`bitcoin.conf` or passed with a leading `-` on the command line.

| Option | Default | Meaning |
| --- | ---: | --- |
| `blockcollector` | Disabled | Target file; enables collection |
| `blockcollectordir` | `block-archive` | Private archive directory |
| `blockcollectoragent` | `/btcd:` | Case-sensitive claimed user-agent substring |
| `blockcollectorinterval` | 2000 | Minimum per-connection request interval |
| `blockcollectorglobalinterval` | 100 | Minimum global request interval |
| `blockcollectortimeout` | 30000 | Request timeout |
| `blockcollectormaxpending` | 16 | Global outstanding-request ceiling |
| `blockcollectormaxbytes` | 1024 | Raw-file budget; minimum 4 |
| `blockcollectormaxfiles` | 10000 | Raw-file count ceiling |
| `blockcollectorloglimit` | 64 | Event-log budget |
| `blockcollectorqueue` | 64 | Queue accounting budget; minimum 4 |
| `blockcollectorqueueitems` | 4096 | Queued/in-progress jobs and reply reservations; minimum 2 |
| `blockcollectormaxtimeouts` | 2 | Consecutive timeouts before suspending a survey |
| `blockcollectorpeerbytes` | 0 | Retention budget per connection; 0 derives the allowance described above |
| `blockcollectorrandomize` | 1 | Random starting offset per connection |

String/path and numeric options require explicit values and reject negation;
empty strings are rejected. Numeric values must be whole numbers without units.
`-noblockcollector` disables collection, and `-noblockcollectorrandomize` disables
random starts. For allowed ranges, consult `bitcoind -help`.
