# NetfilterGuard

**Fall 2024 · SKKU Network System S/W Design (ECE5989) Project**

## Overview

NetfilterGuard is a Linux kernel networking project that implements per-source IPv4 traffic monitoring and temporary packet filtering with Netfilter.

The module registers an `NF_INET_PRE_ROUTING` hook, tracks source addresses in a kernel hash table, and applies bounded fixed-window policies for SYN-heavy, high-rate TCP, and high-rate UDP traffic. Sources that exceed a configured policy are temporarily blocked, while aggregate runtime state is exposed through `/proc/netfilter_guard`.

The project focuses on Linux kernel networking fundamentals: packet-path parsing, kernel data structures, synchronization, timers, state reclamation, and reproducible validation in an isolated network namespace.

## Environment / Technologies

- C
- Linux kernel module (out-of-tree kbuild)
- Linux Netfilter (`NF_INET_PRE_ROUTING`)
- IPv4 / TCP / UDP header inspection
- Kernel hash table (`DEFINE_HASHTABLE`)
- Spinlock synchronization
- `jiffies` and kernel timers
- `/proc` status interface with `seq_file`
- Linux network namespaces and `veth` for isolated validation

Validated environment:

- Ubuntu 20.04.6 LTS
- Linux `5.15.0-139-generic`

## Main Implementation

### Per-source traffic state

Each observed IPv4 source has an independent state entry containing:

- observation-window start time;
- last-seen time;
- SYN count;
- approximate ACK completion count;
- TCP packet count;
- UDP packet count;
- temporary-block expiration time;
- block reason.

This prevents traffic from unrelated source addresses from sharing the same detection counters.

### SYN-heavy traffic detection

For TCP traffic, NetfilterGuard counts inbound SYN attempts and maintains a lightweight ACK/SYN completion heuristic. A source can be temporarily blocked when its SYN count reaches the configured threshold while its approximate completion ratio remains below `min_completion_pct`.

This metric is intentionally a heuristic rather than full TCP connection tracking because the module does not retain complete 4-tuple flow state.

### TCP / UDP rate filtering

TCP and UDP packet counts are maintained independently for each tracked source. Reaching the configured protocol threshold within the current observation window creates a temporary block.

### Bounded source-state table

The number of tracked source addresses is bounded by `max_entries`. Idle, non-blocked entries are periodically reclaimed by a garbage-collection timer. If the table is full, previously unseen sources are left untracked rather than allowing unbounded kernel-memory growth.

### Safe packet inspection

The hook validates the IPv4 header and retrieves transport headers using `skb_header_pointer()`. Fragmented IPv4 packets are counted but are not interpreted as complete TCP/UDP headers.

### Runtime observability

Current configuration and aggregate counters are available through:

```bash
cat /proc/netfilter_guard
```

New block events are also reported using rate-limited kernel log messages.

### Interface-scoped validation

The optional `interface` module parameter restricts inspection to a selected ingress interface. The validation script uses this feature with a temporary `veth` pair so low test thresholds do not affect the host's normal network interface.

## Tests / Validation

The repository includes a one-shot isolated validation script:

```bash
sudo ./scripts/run_isolated_validation.sh
```

It creates a temporary Linux network namespace and `veth` pair, loads NetfilterGuard only on the test interface, generates bounded traffic, records status snapshots, and cleans up the temporary environment on exit.

The validation covers:

1. ordinary TCP connections below the configured thresholds;
2. SYN-heavy traffic with low approximate completion;
3. per-source TCP-rate thresholding;
4. per-source UDP-rate thresholding;
5. temporary blocking and expiration;
6. module unload and namespace cleanup.

See [`tests/README.md`](tests/README.md) for details.

## Evaluation / Results

Runtime validation was completed on Ubuntu 20.04.6 LTS with Linux `5.15.0-139-generic`.

Observed results:

| Validation step | Dropped packets | Cumulative block events | Result |
| --- | ---: | ---: | --- |
| Baseline | 0 | 0 | PASS |
| Ordinary TCP | 0 | 0 | PASS |
| SYN-heavy probe | 21 | 1 | PASS |
| TCP-rate probe | 42 | 2 | PASS |
| UDP-rate probe | 63 | 3 | PASS |

The kernel log distinguished the three filtering reasons:

```text
reason=syn-rate-low-completion
reason=tcp-rate
reason=udp-rate
```

No source-table saturation or allocation failures were observed during this validation run.

The complete recorded output is available in [`results/runtime_validation.txt`](results/runtime_validation.txt).

## How to Build and Run

Build against the headers of the currently running kernel:

```bash
make
```

Load with default parameters:

```bash
sudo ./scripts/load_module.sh
```

Inspect status:

```bash
cat /proc/netfilter_guard
```

Inspect recent log messages:

```bash
sudo dmesg | grep 'netfilter_guard:' | tail -n 30
```

Unload:

```bash
sudo ./scripts/unload_module.sh
```

For isolated validation, install the required tools and run:

```bash
sudo apt update
sudo apt install -y hping3 iproute2
sudo ./scripts/run_isolated_validation.sh
```

## Project Context

This project originated from **Network System Software Design (ECE5989)** at Sungkyunkwan University in **Fall 2024**. The repository was later organized for portfolio publication, with the implementation cleaned up and validated on a Linux 5.15 environment.

## Limitations

- IPv4 only.
- Fixed-window per-source thresholds rather than adaptive traffic modeling.
- ACK/SYN completion is a lightweight heuristic, not complete TCP connection tracking.
- Fragmented IPv4 packets are not inspected at the transport-header level.
- Source-table saturation intentionally leaves previously unseen sources untracked.
- This is an educational host-level traffic-filtering prototype, not a production DDoS mitigation appliance.

## License

GPL-2.0-only. See [`LICENSE`](LICENSE).
