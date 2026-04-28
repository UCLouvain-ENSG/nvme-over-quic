#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* QUIC packet format constants */
#define QUIC_LONG_PACKET_BIT    0x80

/* Map to hold socket file descriptors - sized for up to 64 reactors */
#define MAX_REUSEPORT_SOCKETS 64
struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, MAX_REUSEPORT_SOCKETS);
    __type(key, __u32);
    __type(value, __u32);
} reuseport_array SEC(".maps");

/* Config map: key=0 holds num_sockets (populated by userspace after all sockets are ready) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

/* Debug/stats map:
 * 0..N-1  : per-reactor routing counters (N = num_sockets, up to 64)
 * 64      : total packets
 * 65      : load_bytes errors (packet too short)
 * 66      : bpf_sk_select_reuseport errors
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
} debug_stats SEC(".maps");

SEC("sk_reuseport")
int select_socket(struct sk_reuseport_md *reuse_md) {
    __u32 num_sockets;
    __u32 index;
    __u32 stats_key;
    __u64 *counter;
    __u8 shard_id;
    __u8 buf[16];
    int ret;

    /* Read num_sockets from config map */
    {
        __u32 _cfg_key = 0;
        __u32 *_p = bpf_map_lookup_elem(&config_map, &_cfg_key);
        num_sockets = (_p && *_p > 0) ? *_p : 4;
    }

    /* Increment total packet counter (key=64) */
    stats_key = 64;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    /* Read 16 bytes of QUIC header via bpf_skb_load_bytes.
     * Offset 8 skips the 8-byte UDP header prefix.
     * This works regardless of whether the payload is in the linear
     * region or in SKB frags (GRO / hardware coalescing). */
    if (bpf_skb_load_bytes(reuse_md, 8, buf, sizeof(buf)) != 0) {
        /* Packet too short to contain a QUIC header */
        stats_key = 65;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        index = reuse_md->hash % num_sockets;
        bpf_printk("ERROR: load_bytes failed, hash index=%u", index);
        goto do_select;
    }

    /* buf[0] = first byte of QUIC packet
     * Long header: buf[6] = DCID[0]  (buf[5] = DCID length, buf[1-4] = version)
     * Short header: buf[1] = DCID[0] */
    if (buf[0] & QUIC_LONG_PACKET_BIT)
        shard_id = buf[6];
    else
        shard_id = buf[1];


    index = shard_id % num_sockets;
    // bpf_printk("shard_id=%u num_sockets=%u index=%u", shard_id, num_sockets, index);

    /* Track per-reactor routing counter */
    stats_key = index;
    counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
    if (counter)
        __sync_fetch_and_add(counter, 1);

do_select:
    ret = bpf_sk_select_reuseport(reuse_md, &reuseport_array, &index, 0);
    if (ret < 0) {
        stats_key = 66;
        counter = bpf_map_lookup_elem(&debug_stats, &stats_key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        bpf_printk("ERROR: bpf_sk_select_reuseport failed (ret=%d index=%u)", ret, index);
    }

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";