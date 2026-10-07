// SPDX-License-Identifier: GPL-2.0-only

#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <linux/udp.h>
#include <net/ip.h>

#define NG_HASH_BITS 10
#define NG_PROC_NAME "netfilter_guard"
#define NG_GC_INTERVAL_SECONDS 30U

enum ng_traffic_kind {
	NG_TRAFFIC_OTHER = 0,
	NG_TRAFFIC_TCP,
	NG_TRAFFIC_UDP,
};

enum ng_block_reason {
	NG_BLOCK_NONE = 0,
	NG_BLOCK_SYN_RATE,
	NG_BLOCK_TCP_RATE,
	NG_BLOCK_UDP_RATE,
};

struct ng_source_state {
	__be32 ip;
	unsigned long window_start;
	unsigned long last_seen;
	unsigned long ban_until;
	u32 syn_count;
	u32 ack_count;
	u32 tcp_count;
	u32 udp_count;
	enum ng_block_reason block_reason;
	struct hlist_node node;
};

static DEFINE_HASHTABLE(ng_source_table, NG_HASH_BITS);
static DEFINE_SPINLOCK(ng_table_lock);
static struct timer_list ng_gc_timer;
static struct proc_dir_entry *ng_proc_entry;
static unsigned int ng_tracked_sources;

static atomic64_t ng_total_packets = ATOMIC64_INIT(0);
static atomic64_t ng_dropped_packets = ATOMIC64_INIT(0);
static atomic64_t ng_ban_events = ATOMIC64_INIT(0);
static atomic64_t ng_table_full_events = ATOMIC64_INIT(0);
static atomic64_t ng_allocation_failures = ATOMIC64_INIT(0);
static atomic64_t ng_fragment_packets = ATOMIC64_INIT(0);

static char *interface = "";
module_param(interface, charp, 0444);
MODULE_PARM_DESC(interface,
		 "Optional ingress interface to monitor; empty means all IPv4 ingress interfaces");

static unsigned int window_seconds = 5;
module_param(window_seconds, uint, 0644);
MODULE_PARM_DESC(window_seconds, "Per-source observation window in seconds");

static unsigned int ban_seconds = 60;
module_param(ban_seconds, uint, 0644);
MODULE_PARM_DESC(ban_seconds, "Temporary block duration in seconds");

static unsigned int syn_threshold = 200;
module_param(syn_threshold, uint, 0644);
MODULE_PARM_DESC(syn_threshold, "SYN attempts allowed per source per observation window");

static unsigned int tcp_threshold = 2000;
module_param(tcp_threshold, uint, 0644);
MODULE_PARM_DESC(tcp_threshold, "TCP packets allowed per source per observation window");

static unsigned int udp_threshold = 2000;
module_param(udp_threshold, uint, 0644);
MODULE_PARM_DESC(udp_threshold, "UDP packets allowed per source per observation window");

static unsigned int min_completion_pct = 25;
module_param(min_completion_pct, uint, 0644);
MODULE_PARM_DESC(min_completion_pct,
		 "Minimum approximate ACK/SYN completion percentage before SYN-rate blocking");

static unsigned int idle_timeout_seconds = 300;
module_param(idle_timeout_seconds, uint, 0644);
MODULE_PARM_DESC(idle_timeout_seconds, "Idle source-state lifetime in seconds");

static unsigned int max_entries = 4096;
module_param(max_entries, uint, 0444);
MODULE_PARM_DESC(max_entries, "Maximum number of tracked source addresses");

static const char *ng_reason_string(enum ng_block_reason reason)
{
	switch (reason) {
	case NG_BLOCK_SYN_RATE:
		return "syn-rate-low-completion";
	case NG_BLOCK_TCP_RATE:
		return "tcp-rate";
	case NG_BLOCK_UDP_RATE:
		return "udp-rate";
	case NG_BLOCK_NONE:
	default:
		return "none";
	}
}

static bool ng_interface_matches(const struct nf_hook_state *state)
{
	if (!interface || interface[0] == '\0')
		return true;

	if (!state || !state->in)
		return false;

	return strncmp(state->in->name, interface, IFNAMSIZ) == 0;
}

static struct ng_source_state *ng_find_source_locked(__be32 ip)
{
	struct ng_source_state *entry;

	hash_for_each_possible(ng_source_table, entry, node, (__force u32)ip) {
		if (entry->ip == ip)
			return entry;
	}

	return NULL;
}

static struct ng_source_state *ng_get_or_create_source_locked(__be32 ip,
						       unsigned long now)
{
	struct ng_source_state *entry;

	entry = ng_find_source_locked(ip);
	if (entry)
		return entry;

	if (ng_tracked_sources >= max_entries) {
		atomic64_inc(&ng_table_full_events);
		return NULL;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		atomic64_inc(&ng_allocation_failures);
		return NULL;
	}

	entry->ip = ip;
	entry->window_start = now;
	entry->last_seen = now;
	entry->ban_until = 0;
	entry->block_reason = NG_BLOCK_NONE;
	hash_add(ng_source_table, &entry->node, (__force u32)ip);
	ng_tracked_sources++;

	return entry;
}

static void ng_reset_window(struct ng_source_state *entry,
			    unsigned long now)
{
	entry->window_start = now;
	entry->syn_count = 0;
	entry->ack_count = 0;
	entry->tcp_count = 0;
	entry->udp_count = 0;
}

static void ng_apply_ban_locked(struct ng_source_state *entry,
				unsigned long now,
				enum ng_block_reason reason)
{
	entry->ban_until = now + (unsigned long)ban_seconds * HZ;
	entry->block_reason = reason;
	atomic64_inc(&ng_ban_events);
}

static bool ng_evaluate_source(__be32 src_ip, enum ng_traffic_kind kind,
			       bool syn, bool ack)
{
	struct ng_source_state *entry;
	unsigned long now = jiffies;
	unsigned long window_jiffies = (unsigned long)window_seconds * HZ;
	bool drop = false;
	bool new_ban = false;
	enum ng_block_reason reason = NG_BLOCK_NONE;
	u32 syn_snapshot = 0;
	u32 ack_snapshot = 0;
	u32 tcp_snapshot = 0;
	u32 udp_snapshot = 0;

	spin_lock_bh(&ng_table_lock);

	entry = ng_get_or_create_source_locked(src_ip, now);
	if (!entry) {
		spin_unlock_bh(&ng_table_lock);
		return false;
	}

	entry->last_seen = now;

	if (entry->ban_until && time_before(now, entry->ban_until)) {
		drop = true;
		goto out_unlock;
	}

	if (entry->ban_until && time_after_eq(now, entry->ban_until)) {
		entry->ban_until = 0;
		entry->block_reason = NG_BLOCK_NONE;
	}

	if (time_after_eq(now, entry->window_start + window_jiffies))
		ng_reset_window(entry, now);

	if (kind == NG_TRAFFIC_TCP) {
		entry->tcp_count++;

		if (syn && !ack)
			entry->syn_count++;
		else if (ack && !syn && entry->ack_count < entry->syn_count)
			entry->ack_count++;

		if (entry->syn_count >= syn_threshold) {
			u64 completion_pct;

			completion_pct = entry->syn_count ?
				((u64)entry->ack_count * 100ULL) / entry->syn_count : 100ULL;

			if (completion_pct < min_completion_pct) {
				reason = NG_BLOCK_SYN_RATE;
				ng_apply_ban_locked(entry, now, reason);
				drop = true;
				new_ban = true;
			}
		}

		if (!new_ban && entry->tcp_count >= tcp_threshold) {
			reason = NG_BLOCK_TCP_RATE;
			ng_apply_ban_locked(entry, now, reason);
			drop = true;
			new_ban = true;
		}
	} else if (kind == NG_TRAFFIC_UDP) {
		entry->udp_count++;
		if (entry->udp_count >= udp_threshold) {
			reason = NG_BLOCK_UDP_RATE;
			ng_apply_ban_locked(entry, now, reason);
			drop = true;
			new_ban = true;
		}
	}

	if (new_ban) {
		syn_snapshot = entry->syn_count;
		ack_snapshot = entry->ack_count;
		tcp_snapshot = entry->tcp_count;
		udp_snapshot = entry->udp_count;
	}

out_unlock:
	spin_unlock_bh(&ng_table_lock);

	if (drop)
		atomic64_inc(&ng_dropped_packets);

	if (new_ban) {
		pr_warn_ratelimited(
			"netfilter_guard: blocked source=%pI4 reason=%s syn=%u ack=%u tcp=%u udp=%u ban=%us\n",
			&src_ip, ng_reason_string(reason), syn_snapshot, ack_snapshot,
			tcp_snapshot, udp_snapshot, ban_seconds);
	}

	return drop;
}

static unsigned int ng_hook(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr tcp_buf;
	struct udphdr udp_buf;
	const struct tcphdr *tcph;
	const struct udphdr *udph;
	unsigned int network_offset;
	unsigned int ip_header_len;
	unsigned int transport_offset;
	enum ng_traffic_kind kind = NG_TRAFFIC_OTHER;
	bool syn = false;
	bool ack = false;

	(void)priv;

	if (!skb || !ng_interface_matches(state))
		return NF_ACCEPT;

	atomic64_inc(&ng_total_packets);

	network_offset = skb_network_offset(skb);
	if (!pskb_may_pull(skb, network_offset + sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return NF_ACCEPT;

	ip_header_len = iph->ihl * 4U;
	if (!pskb_may_pull(skb, network_offset + ip_header_len))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if (ip_is_fragment(iph)) {
		atomic64_inc(&ng_fragment_packets);
		return ng_evaluate_source(iph->saddr, NG_TRAFFIC_OTHER, false, false) ?
			NF_DROP : NF_ACCEPT;
	}

	transport_offset = network_offset + ip_header_len;

	if (iph->protocol == IPPROTO_TCP) {
		tcph = skb_header_pointer(skb, transport_offset,
					 sizeof(tcp_buf), &tcp_buf);
		if (tcph && tcph->doff >= 5) {
			kind = NG_TRAFFIC_TCP;
			syn = tcph->syn;
			ack = tcph->ack;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = skb_header_pointer(skb, transport_offset,
					 sizeof(udp_buf), &udp_buf);
		if (udph)
			kind = NG_TRAFFIC_UDP;
	}

	return ng_evaluate_source(iph->saddr, kind, syn, ack) ? NF_DROP : NF_ACCEPT;
}

static struct nf_hook_ops ng_nf_ops = {
	.hook = ng_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static void ng_gc_timer_fn(struct timer_list *timer)
{
	struct ng_source_state *entry;
	struct hlist_node *tmp;
	unsigned long now = jiffies;
	unsigned long idle_jiffies = (unsigned long)idle_timeout_seconds * HZ;
	int bucket;

	(void)timer;

	spin_lock_bh(&ng_table_lock);
	hash_for_each_safe(ng_source_table, bucket, tmp, entry, node) {
		bool banned = entry->ban_until && time_before(now, entry->ban_until);

		if (!banned && time_after_eq(now, entry->last_seen + idle_jiffies)) {
			hash_del(&entry->node);
			kfree(entry);
			ng_tracked_sources--;
		}
	}
	spin_unlock_bh(&ng_table_lock);

	mod_timer(&ng_gc_timer, jiffies + (unsigned long)NG_GC_INTERVAL_SECONDS * HZ);
}

static int ng_status_show(struct seq_file *m, void *v)
{
	(void)v;

	seq_puts(m, "NetfilterGuard status\n");
	seq_printf(m, "interface: %s\n",
		   (interface && interface[0] != '\0') ? interface : "all");
	seq_printf(m, "tracked_sources: %u\n", READ_ONCE(ng_tracked_sources));
	seq_printf(m, "total_packets: %lld\n",
		   (long long)atomic64_read(&ng_total_packets));
	seq_printf(m, "dropped_packets: %lld\n",
		   (long long)atomic64_read(&ng_dropped_packets));
	seq_printf(m, "ban_events: %lld\n",
		   (long long)atomic64_read(&ng_ban_events));
	seq_printf(m, "fragment_packets: %lld\n",
		   (long long)atomic64_read(&ng_fragment_packets));
	seq_printf(m, "table_full_events: %lld\n",
		   (long long)atomic64_read(&ng_table_full_events));
	seq_printf(m, "allocation_failures: %lld\n",
		   (long long)atomic64_read(&ng_allocation_failures));
	seq_printf(m, "window_seconds: %u\n", window_seconds);
	seq_printf(m, "ban_seconds: %u\n", ban_seconds);
	seq_printf(m, "syn_threshold: %u\n", syn_threshold);
	seq_printf(m, "tcp_threshold: %u\n", tcp_threshold);
	seq_printf(m, "udp_threshold: %u\n", udp_threshold);
	seq_printf(m, "min_completion_pct: %u\n", min_completion_pct);
	seq_printf(m, "idle_timeout_seconds: %u\n", idle_timeout_seconds);
	seq_printf(m, "max_entries: %u\n", max_entries);

	return 0;
}

static int ng_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, ng_status_show, NULL);
}

static const struct proc_ops ng_proc_ops = {
	.proc_open = ng_status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static bool ng_parameters_valid(void)
{
	if (!window_seconds || !ban_seconds || !syn_threshold ||
	    !tcp_threshold || !udp_threshold || !idle_timeout_seconds ||
	    !max_entries || min_completion_pct > 100)
		return false;

	if (interface && strnlen(interface, IFNAMSIZ) >= IFNAMSIZ)
		return false;

	return true;
}

static int __init ng_init(void)
{
	int ret;

	if (!ng_parameters_valid()) {
		pr_err("netfilter_guard: invalid module parameter configuration\n");
		return -EINVAL;
	}

	hash_init(ng_source_table);
	timer_setup(&ng_gc_timer, ng_gc_timer_fn, 0);

	ng_proc_entry = proc_create(NG_PROC_NAME, 0444, NULL, &ng_proc_ops);
	if (!ng_proc_entry) {
		pr_err("netfilter_guard: failed to create /proc/%s\n", NG_PROC_NAME);
		return -ENOMEM;
	}

	ret = nf_register_net_hook(&init_net, &ng_nf_ops);
	if (ret) {
		proc_remove(ng_proc_entry);
		ng_proc_entry = NULL;
		pr_err("netfilter_guard: failed to register Netfilter hook: %d\n", ret);
		return ret;
	}

	mod_timer(&ng_gc_timer, jiffies + (unsigned long)NG_GC_INTERVAL_SECONDS * HZ);

	pr_info("netfilter_guard: loaded interface=%s window=%us syn=%u tcp=%u udp=%u ban=%us max_entries=%u\n",
		(interface && interface[0] != '\0') ? interface : "all",
		window_seconds, syn_threshold, tcp_threshold, udp_threshold,
		ban_seconds, max_entries);

	return 0;
}

static void __exit ng_exit(void)
{
	struct ng_source_state *entry;
	struct hlist_node *tmp;
	int bucket;

	nf_unregister_net_hook(&init_net, &ng_nf_ops);
	del_timer_sync(&ng_gc_timer);

	if (ng_proc_entry) {
		proc_remove(ng_proc_entry);
		ng_proc_entry = NULL;
	}

	spin_lock_bh(&ng_table_lock);
	hash_for_each_safe(ng_source_table, bucket, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	ng_tracked_sources = 0;
	spin_unlock_bh(&ng_table_lock);

	pr_info("netfilter_guard: unloaded\n");
}

module_init(ng_init);
module_exit(ng_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sangwon");
MODULE_DESCRIPTION("Per-source IPv4 flood monitoring and temporary filtering with Linux Netfilter");
