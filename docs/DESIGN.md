# NetfilterGuard Design

## Packet path

NetfilterGuard registers an IPv4 hook at `NF_INET_PRE_ROUTING`. For each packet it:

1. optionally checks whether the ingress interface matches the configured interface;
2. validates the IPv4 header;
3. detects IPv4 fragmentation and avoids transport-header assumptions for fragments;
4. retrieves TCP or UDP headers with `skb_header_pointer()` when available;
5. looks up or creates source-address state;
6. resets the source's counters when its observation window expires;
7. updates protocol, SYN, and completion counters;
8. applies a temporary block when a configured policy is triggered.

## Per-source state

Each tracked IPv4 source stores:

- observation-window start time;
- last-seen time;
- SYN count;
- approximate ACK completion count;
- TCP packet count;
- UDP packet count;
- block expiration time;
- block reason.

The source table is bounded by `max_entries`. If it is full, a previously unseen source is left untracked rather than allowing unbounded kernel-memory growth.

## Detection rules

### SYN-heavy traffic

A source is temporarily blocked when its SYN count reaches `syn_threshold` within the current observation window and its approximate ACK/SYN completion percentage remains below `min_completion_pct`.

The ACK/SYN metric is a heuristic because the module does not retain complete TCP 4-tuples or perform full connection tracking.

### TCP / UDP packet rate

A source is temporarily blocked when its TCP or UDP packet count reaches the corresponding threshold within the current observation window.

## State reclamation

A single timer periodically removes entries that are both not currently blocked and idle longer than `idle_timeout_seconds`.

During module unload, the timer is stopped with `del_timer_sync()` before the source table is destroyed.

## Observability

`/proc/netfilter_guard` exposes configuration and aggregate counters including:

- tracked sources;
- total observed packets;
- dropped packets;
- block events;
- fragmented packets;
- source-table saturation events;
- allocation failures.

New temporary blocks are reported with `pr_warn_ratelimited()`.

## Isolated validation

The `interface` module parameter can restrict inspection to a selected ingress interface. The validation script creates a temporary `veth` pair and loads the module with `interface=nfg-host`, preventing test thresholds from being applied to the host's normal network interface.
